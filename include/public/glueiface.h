/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   glueiface.h
///
/// @brief  Defines an interface used by the introspection engine to communicate with an integrator.
///
/// Part of the interface is implemented by the introspection engine, allowing an integrator
/// to control its behavior, while the other part needs support from the underlying hypervisor.
///
/// @ingroup group_public_headers
///

#ifndef _GLUEIFACE_H_
#define _GLUEIFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "intro_types.h"
#include "upperiface.h"

#pragma pack(push)
#pragma pack(8)

/// @brief  Holds register state.
typedef struct _IG_ARCH_REGS
{
    QWORD Rax;
    QWORD Rcx;
    QWORD Rdx;
    QWORD Rbx;
    QWORD Rsp;
    QWORD Rbp;
    QWORD Rsi;
    QWORD Rdi;
    QWORD R8;
    QWORD R9;
    QWORD R10;
    QWORD R11;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;
    QWORD Cr2;
    QWORD Flags;
    QWORD Dr7;
    QWORD Rip;
    QWORD Cr0;
    QWORD Cr4;
    QWORD Cr3;
    QWORD Cr8;
    QWORD IdtBase;
    QWORD IdtLimit;
    QWORD GdtBase;
    QWORD GdtLimit;

} IG_ARCH_REGS, *PIG_ARCH_REGS;

/// @brief  Holds segment register state.
typedef struct _IG_SEG_REGS
{
    QWORD       CsBase;
    QWORD       CsLimit;
    QWORD       CsSelector;
    QWORD       CsAr;
    QWORD       SsBase;
    QWORD       SsLimit;
    QWORD       SsSelector;
    QWORD       SsAr;
    QWORD       DsBase;
    QWORD       DsLimit;
    QWORD       DsSelector;
    QWORD       DsAr;
    QWORD       EsBase;
    QWORD       EsLimit;
    QWORD       EsSelector;
    QWORD       EsAr;
    QWORD       FsBase;
    QWORD       FsLimit;
    QWORD       FsSelector;
    QWORD       FsAr;
    QWORD       GsBase;
    QWORD       GsLimit;
    QWORD       GsSelector;
    QWORD       GsAr;
} IG_SEG_REGS, *PIG_SEG_REGS;

/// @brief  Describes an XSAVE area format.
typedef struct _IG_XSAVE_AREA
{
    WORD            Fcw;
    WORD            Fsw;
    BYTE            Ftw;
    BYTE            Rsvd1;
    WORD            Fop;
    QWORD           Fip;

    QWORD           Fdp;
    DWORD           Mxcsr;
    DWORD           MxcsrMask;

    QWORD           Mm0[2];
    QWORD           Mm1[2];
    QWORD           Mm2[2];
    QWORD           Mm3[2];
    QWORD           Mm4[2];
    QWORD           Mm5[2];
    QWORD           Mm6[2];
    QWORD           Mm7[2];
    QWORD           Xmm0[2];
    QWORD           Xmm1[2];
    QWORD           Xmm2[2];
    QWORD           Xmm3[2];
    QWORD           Xmm4[2];
    QWORD           Xmm5[2];
    QWORD           Xmm6[2];
    QWORD           Xmm7[2];
    QWORD           Xmm8[2];
    QWORD           Xmm9[2];
    QWORD           Xmm10[2];
    QWORD           Xmm11[2];
    QWORD           Xmm12[2];
    QWORD           Xmm13[2];
    QWORD           Xmm14[2];
    QWORD           Xmm15[2];
    BYTE            Rsvd2[96];
    BYTE            ExtendedArea[3584];
} IG_XSAVE_AREA, *PIG_XSAVE_AREA;


//
// MSR definitions
//
#define IG_IA32_SYSENTER_CS         0x00000174
#define IG_IA32_SYSENTER_ESP        0x00000175
#define IG_IA32_SYSENTER_EIP        0x00000176
#define IG_IA32_MISC_ENABLE         0x000001A0
#define IG_IA32_PAT                 0x00000277
#define IG_IA32_MC0_CTL             0x00000400
#define IG_IA32_EFER                0xC0000080
#define IG_IA32_STAR                0xC0000081
#define IG_IA32_LSTAR               0xC0000082
#define IG_IA32_FS_BASE             0xC0000100
#define IG_IA32_GS_BASE             0xC0000101
#define IG_IA32_KERNEL_GS_BASE      0xC0000102
#define IG_IA32_LBR_TOS             0x000001C9
#define IG_IA32_DEBUGCTL            0x000001D9


///
/// @brief  Memory type values.
///
typedef enum
{
    IG_MEM_UC = 0x0,        ///< Uncacheable.
    IG_MEM_WC = 0x1,        ///< Write-combining.
    IG_MEM_WT = 0x4,        ///< Write-through.
    IG_MEM_WP = 0x5,        ///< Write-protect.
    IG_MEM_WB = 0x6,        ///< Write-back.
    IG_MEM_UC_MINUS = 0x7,
    IG_MEM_UNKNOWN = 0xFF,  ///< Unknown memory type.
} IG_MEMTYPE;

///
/// @brief  The type of the MSR access.
///
typedef enum
{
    IG_MSR_HOOK_READ = 1,   ///< Read access.
    IG_MSR_HOOK_WRITE,      ///< Write access.
    IG_MSR_HOOK_BOTH = (IG_MSR_HOOK_READ | IG_MSR_HOOK_WRITE),  ///< Read-write access.
} IG_MSR_HOOK_TYPE;



///
/// @brief  The type of the code segment
///
typedef enum
{
    IG_CS_TYPE_INVALID = 0, ///< Invalid selector.
    IG_CS_TYPE_16B,         ///< 16-bit selector.
    IG_CS_TYPE_32B,         ///< 32-bit selector.
    IG_CS_TYPE_64B,         ///< 64-bit selector.
} IG_CS_TYPE;


///
/// @brief  The current protection level.
///
typedef enum
{
    IG_CS_RING_0 = 0,
    IG_CS_RING_1,
    IG_CS_RING_2,
    IG_CS_RING_3,
} IG_CS_RING;


///
/// @brief  The MSR query structure.
///
/// On #GLUE_IFACE.QueryGuestInfo calls that have InfoClass set to IG_QUERY_INFO_CLASS_READ_MSR,
/// the Buffer parameter will point to a structure of this type.
///
typedef struct _IG_QUERY_MSR
{
    DWORD MsrId;    ///< The ID of the MSR, as defined by Intel.
    QWORD Value;    ///< The value of the MSR.
} IG_QUERY_MSR, *PIG_QUERY_MSR;


///
/// @brief  Describes the type of query done by #GLUE_IFACE.QueryGuestInfo.
///
typedef enum
{
    /// Get the guest register state for a VCPU. Buffer points to a #IG_ARCH_REGS structure.
    IG_QUERY_INFO_CLASS_REGISTER_STATE = 0,

    /// Get the value of a MSR for a VCPU. Buffer points to a #IG_QUERY_MSR structure.
    IG_QUERY_INFO_CLASS_READ_MSR,

    /// Get the value of the IDT base for a VCPU.
    IG_QUERY_INFO_CLASS_IDT,

    /// Get the value of the IDT base for a VCPU.
    IG_QUERY_INFO_CLASS_GDT,

    /// Get the number of VCPUs available to the guest.
    IG_QUERY_INFO_CLASS_CPU_COUNT,

    /// Set the guest register state for a certain VCPU. Buffer points to a #IG_ARCH_REGS structure.
    /// Should not set #IG_ARCH_REGS.IdtBase, #IG_ARCH_REGS.IdtLimit, #IG_ARCH_REGS.GdtBase or #IG_ARCH_REGS.GdtLimit.
    IG_QUERY_INFO_CLASS_SET_REGISTERS,

    /// Get the TSC speed.
    IG_QUERY_INFO_CLASS_TSC_SPEED,

    /// Get the current VCPU number.
    IG_QUERY_INFO_CLASS_CURRENT_TID,

    /// Similar to IG_QUERY_INFO_CLASS_REGISTER_STATE, but will get only the general purpose registers, from RAX to R15.
    IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS,

    /// Get the code segment type for a VCPU. Buffer points to a #IG_CS_TYPE enum.
    IG_QUERY_INFO_CLASS_CS_TYPE,

    /// Get the current privilege level for a VCPU. Buffer points to a #IG_CS_RING enum.
    IG_QUERY_INFO_CLASS_CS_RING,

    /// Get the segment registers for the current VCPU. Buffer points to a #IG_SEG_REGS structure.
    IG_QUERY_INFO_CLASS_SEG_REGISTERS,

    /// Get the size of the guest XSAVE area for a VCPU.
    IG_QUERY_INFO_CLASS_XSAVE_SIZE,

    /// Get the guest XSAVE area for a VCPU.
    IG_QUERY_INFO_CLASS_XSAVE_AREA,

    /// Get the current EPTP index for the current VCPU.
    IG_QUERY_INFO_CLASS_EPTP_INDEX,

    /// Get the max guest physical frame number available to the guest. This should be the last valid PFN
    /// available to the guest.
    IG_QUERY_INFO_CLASS_MAX_GPFN,

    /// Set the guest XSAVE area for a VCPU. This query is optional.
    IG_QUERY_INFO_CLASS_SET_XSAVE_AREA,

    /// Get the guest XCR0 value for a VCPU.
    IG_QUERY_INFO_CLASS_GET_XCR0,

    /// Get the availability of the Virtualization Exception feature in hardware and the hypervisor.
    IG_QUERY_INFO_CLASS_VE_SUPPORT = 100,

    /// Get the availability of the VMFUNC feature in hardware and the hypervisor.
    IG_QUERY_INFO_CLASS_VMFUNC_SUPPORT,

    /// Get the availability of the SPP feature in hardware and the hypervisor.
    IG_QUERY_INFO_CLASS_SPP_SUPPORT,

    /// Get the availability of the IDTR/GDTR exits.
    IG_QUERY_INFO_CLASS_DTR_SUPPORT,
} IG_QUERY_INFO_CLASS;


///
/// @brief  Ept violation types
///
typedef enum _IG_EPT_HOOK_TYPE
{
    IG_EPT_HOOK_NONE = 0,       ///< No access type. This can be used for swap hooks.
    IG_EPT_HOOK_READ = 1,       ///< Read-access hook.
    IG_EPT_HOOK_WRITE = 2,      ///< Write-access hook.
    IG_EPT_HOOK_EXECUTE = 4,    ///< Execute-access hook.
} IG_EPT_HOOK_TYPE;

typedef BYTE IG_EPT_ACCESS;

///
/// @brief  Descriptor table access flags.
///
/// IG_DESC_ACCESS_READ and IG_DESC_ACCESS_WRITE can be combined with any of the other values, describing both the
/// descriptor table register that was accessed and the access type.
///
typedef enum _IG_DESC_ACCESS
{
    IG_DESC_ACCESS_IDTR = 0x01,     ///< IDTR access.
    IG_DESC_ACCESS_GDTR = 0x02,     ///< GDTR access.
    IG_DESC_ACCESS_TR = 0x04,       ///< TR access.
    IG_DESC_ACCESS_LDTR = 0x08,     ///< LDTR access.

    IG_DESC_ACCESS_READ = 0x10,     ///< Read access.
    IG_DESC_ACCESS_WRITE = 0x20,    ///< Write access.
} IG_DESC_ACCESS;


/// For APIs that take a VCPU number as a parameter, this can be used to specify that the current VCPU should be used.
#define IG_CURRENT_VCPU                     0xFFFFFFFF

/// For APIs that take an ETPT index as a parameter, this can be used to specify that the current EPT should be used.
#define IG_CURRENT_EPT                      0xFFFFFFFF

#define IG_INVALID_TIME                     0xFFFFFFFFFFFFFFFF


///
/// @brief  Deployable agent tags.
///
typedef enum
{
    /// Dummy agent used to demo the feature.
    IG_AGENT_TAG_DUMMY_TOOL = INTRO_AGENT_TAG_DUMMY_TOOL,

    /// The remediation tool agent.
    IG_AGENT_TAG_REMEDIATION_TOOL = INTRO_AGENT_TAG_REMEDIATION_TOOL,

    /// The Linux version of the remediation tool.
    IG_AGENT_TAG_REMEDIATION_TOOL_LINUX = INTRO_AGENT_TAG_REMEDIATION_TOOL_LINUX,

    /// The log gathering agent.
    IG_AGENT_TAG_LOG_GATHER_TOOL = INTRO_AGENT_TAG_LOG_GATHER_TOOL,

    /// The process killer agent.
    IG_AGENT_TAG_AGENT_KILLER_TOOL = INTRO_AGENT_TAG_AGENT_KILLER_TOOL,

    /// The Virtualization exception driver.
    IG_AGENT_TAG_VE_DRIVER = INTRO_AGENT_TAG_VE_DRIVER,

    /// The page table filtering agent.
    IG_AGENT_TAG_PT_DRIVER = INTRO_AGENT_TAG_PT_DRIVER,

    /// A custom tool.
    IG_AGENT_TAG_CUSTOM_TOOL = INTRO_AGENT_TAG_CUSTOM_TOOL,
} IG_AGENT_TAG;


/// If passed to #GLUE_IFACE.DisableIntro, will cause introcore to unload even if this will left the guest in an
/// unstable state.
#define IG_DISABLE_IGNORE_SAFENESS          0x02

/// Signals that a physical mapping request should bypass any existing caches.
#define IG_PHYSMAP_NO_CACHE                 0x00000001

/// The timer frequency (1 call per second).
#define IG_TIMER_FREQUENCY                  1


///
/// @brief  The guest power state.
///
typedef enum _IG_GUEST_POWER_STATE
{
    intGuestPowerStateResume = 1,   ///< The guest is resuming from hibernate or sleep.
    intGuestPowerStateSleep,        ///< The guest is entering sleep.
    intGuestPowerStateShutDown,     ///< The guest is shutting down.
    intGuestPowerStateTerminating,  ///< The guest is shutting down by force.
} IG_GUEST_POWER_STATE;


///
/// @brief  Controls the verbosity of the logs.
///
typedef enum _IG_LOG_LEVEL
{
    intLogLevelDebug,       ///< Shows all logs.
    intLogLevelInfo,        ///< Shows informational logs and logs with a higher level.
    intLogLevelWarning,     ///< Shows warning logs and logs with a higher level.
    intLogLevelError,       ///< Shows error logs and logs with a higher level.
    intLogLevelCritical,    ///< Shows only critical logs.
} IG_LOG_LEVEL;


//
// GLUE INTERFACE callbacks
//

//
// Callbacks registered from INTRO to the HV
//


///
/// Callback that must be invoked on EPT violation VMEXITs. The introspection engines registers a callback of this
/// type with the #GLUE_IFACE.RegisterEPTHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  PhysicalAddress     The physical address for which the exit was triggered.
/// @param[in]  Length              The size of the access that triggered exit.
/// @param[in]  VirtualAddress      The guest linear address for which the exit was triggered.
/// @param[in]  CpuNumber           The virtual CPU for which the exit was triggered.
/// @param[out] Action              The action that must be taken.
/// @param[in]  Type                The type of the access. Can be a combination of #IG_EPT_HOOK_TYPE values.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval    #INT_STATUS_FORCE_ACTION_ON_BETA if the action should be taken even if the introspection
///            engine is in log only (beta) mode.
/// @retval    #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval    #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntEPTViolationCallback)(
    _In_ void *GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD VirtualAddress,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action,
    _In_ IG_EPT_ACCESS Type
    );

///
/// Callback that must be invoked on MSR violation VMEXITs. The introspection engines
/// registers a callback of this type with the #GLUE_IFACE.RegisterMSRHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  Msr                 The physical MSR for which the exit was triggered.
/// @param[in]  Flags               Flags describing the access.
/// @param[out] Action              The action that must be taken.
/// @param[in]  OriginalValue       The original value of the MSR.
/// @param[out] NewValue            The new value of the MSR, after introcore handled the access.
/// @param[in]  CpuNumber           The virtual CPU for which the exit was triggered.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval    #INT_STATUS_NOT_FOUND if introcore is not monitoring accesses done to this MSR.
/// @retval    #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval    #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntMSRViolationCallback)(
    _In_ void *GuestHandle,
    _In_ DWORD Msr,
    _In_ IG_MSR_HOOK_TYPE Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ QWORD OriginalValue,
    _Out_ QWORD *NewValue,
    _In_ DWORD CpuNumber
    );

///
/// Callback that must be invoked when the guest executes a VMCALL. The introspection engine
/// registers a callback of this type with the #GLUE_IFACE.RegisterIntroCallHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  Rip                 The guest linear address of the VMCALL instruction.
/// @param[in]  Cpu                 The VCPU number on which the VMCALL was executed.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval    #INT_STATUS_NOT_FOUND if this VMCALL was not issued for the introspection engine.
/// @retval    #INT_STATUS_UNINIT_BUGCHECK if introcore is unloading as a result of a guest crash.
/// @retval    #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval    #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntIntroCallCallback)(
    _In_ void *GuestHandle,
    _In_ QWORD Rip,
    _In_ DWORD Cpu
    );

///
/// A periodic timer callback that must be invoked once per second. The introspection engine
/// registers a callback of this type with the #GLUE_IFACE.RegisterIntroTimerHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
///
typedef INTSTATUS
(*PFUNC_IntIntroTimerCallback)(
    _In_ void *GuestHandle
    );

///
/// Callback that must be invoked when the guest accesses a descriptor table register. The introspection
/// engine registers a callback of this type with the #GLUE_IFACE.RegisterDtrHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  Flags               Flags that describe the access. Can be a combination of #IG_DESC_ACCESS values.
/// @param[in]  CpuNumber           The VCPU on which the access was attempted.
/// @param[out] Action              Action that must be taken.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval    #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval    #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntIntroDescriptorTableCallback)(
    _In_ void *GuestHandle,
    _In_ DWORD Flags,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    );

///
/// Callback that must be invoked when the guest tries to modify a control register. The introspection
/// engine registers a callback of this type with the #GLUE_IFACE.RegisterCrWriteHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  Cr                  The control register that was accessed.
/// @param[in]  CpuNumber           The VCPU on which the access was attempted.
/// @param[in]  OldValue            The original value of the register.
/// @param[in]  NewValue            The value that the guest attempted to write.
/// @param[out] Action              The action that must be taken.
///
/// @retval    #INT_STATUS_SUCCESS in case of success.
/// @retval    #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval    #INT_STATUS_NOT_FOUND if introcore is not monitoring this control register.
/// @retval    #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval    #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntCrWriteCallback)(
    _In_ void *GuestHandle,
    _In_ DWORD Cr,
    _In_ DWORD CpuNumber,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    );

///
/// Callback that must be invoked when the guest tries to modify an extended control register.
/// The introspection engine registers a callback of this type with the #GLUE_IFACE.RegisterXcrWriteHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  CpuNumber           The VCPU on which the access was attempted.
/// @param[out] Action              The action that must be taken.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval     #INT_STATUS_NOT_FOUND if introcore is not monitoring this control register.
/// @retval     #INT_STATUS_UNINIT_BUGCHECK if introcore is unloading as a result of a guest crash.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval     #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntXcrWriteCallback)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    );

///
/// Callback that must be invoked when the guest hits a breakpoint. The introspection engine
/// registers a callback of this type with the #GLUE_IFACE.RegisterBreakpointHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  PhysicalAddress     The guest physical address at which the instruction that triggered the breakpoint
///                                 is located.
/// @param[in]  CpuNumber           The VCPU on which the access was attempted.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
/// @retval     #INT_STATUS_NOT_FOUND if this INT3 is not monitored by introcore.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if the exit could not be handled due to an internal error.
/// @retval     #INT_STATUS_FATAL_ERROR if an unrecoverable error was encountered.
///
typedef INTSTATUS
(*PFUNC_IntBreakpointCallback)(
    _In_ void *GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD CpuNumber
    );

///
/// Callback that must be invoked when an exception is successfully injected inside the guest.
/// The introspection engine registers a callback of this type with the #GLUE_IFACE.RegisterEventInjectionHandler API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier
/// @param[in]  Vector              The exception vector that was injected
/// @param[in]  ErrorCode           The error code of the injected exception, if it exists
/// @param[in]  Cr2                 The Cr3 value. This parameter is valid only for page fault injections
/// @param[in]  CpuNumber           The VCPU on which the access was attempted
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
///
typedef INTSTATUS
(*PFUNC_IntEventInjectionCallback)(
    _In_ void *GuestHandle,
    _In_ DWORD Vector,
    _In_ QWORD ErrorCode,
    _In_ QWORD Cr2,
    _In_ DWORD CpuNumber
    );

///
/// Optional callback that must be invoked with the result of additional, external, scanning methods.
/// The introspection engine registers a callback of this type with the #GLUE_IFACE.RegisterEnginesResultCallback API.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  EngineNotification  A pointer to a engine notification structure that was provided by introcore
///                                 with a #GLUE_IFACE.NotifyScanEngines API call.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the introspection engine was not initialized.
///
/// @remarks    Every #GLUE_IFACE.NotifyScanEngines call made by introcore must be matched by an invocation of this
///             callback, otherwise the resources allocated for the EngineNotification structures will not be freed.
///
typedef INTSTATUS
(*PFUNC_IntEventEnginesResultCallback)(
    _In_ void *GuestHandle,
    _In_ PENG_NOTIFICATION_HEADER EngineNotification
    );


//
// API exposed by the HV to the introspection
//

///
/// @brief      API exposed by the integrator that allows introcore to obtain various information about the guest.
///
/// Based on the InfoClass value, the functions should get or set different guest attributes, as follows.
/// See #IG_QUERY_INFO_CLASS.
/// 
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  InfoClass       Can be any of the IG_QUERY_INFO_CLASS values. The other parameters.
///                             have different meanings based on the value of this parameter
/// @param[in]  InfoParam       For IG_QUERY_INFO_CLASS values that specify a VCPU number, it is the VCPU number.
///                             For the others it is not used. It can be IG_CURRENT_VCPU for the current VCPU.
/// @param[in, out] Buffer      It has different meanings based on InfoClass. See above for details.
/// @param[in]  BufferLength    The size of Buffer, in bytes.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntQueryGuestInfo)(
    _In_ void *GuestHandle,
    _In_ DWORD InfoClass,
    _In_opt_ void *InfoParam,
    _When_(InfoClass == IG_QUERY_INFO_CLASS_SET_REGISTERS, _In_reads_bytes_(BufferLength))
    _When_(InfoClass != IG_QUERY_INFO_CLASS_SET_REGISTERS, _Out_writes_bytes_(BufferLength))
    void *Buffer,
    _In_ DWORD BufferLength
    );

///
/// @brief  Used by introcore to report events to the integrator.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  EventClass      One of the INTRO_EVENT_TYPE values, specifying the type of event.
/// @param[in]  Parameters      A pointer to a event specific structure. Once this function returns, the Parameters
///                             buffer is no longer valid.
/// @param[in]  EventSize       The size of the Parameters buffer.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyIntroAlert)(
    _In_ void *GuestHandle,
    _In_ DWORD EventClass,
    _In_opt_ void *Parameters,
    _In_ size_t EventSize
    );

///
/// @brief  If implemented, introcore can use this API to signal that an additional memory scan.
/// can be done
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Parameters      A pointer to an event specific structure: either #ENG_NOTIFICATION_CODE_EXEC,
///                             or #ENG_NOTIFICATION_CMD_LINE. The buffer always starts with a #ENG_NOTIFICATION_HEADER,
///                             so the type of the event can be determined based on #ENG_NOTIFICATION_HEADER.Type. The
///                             buffer remains valid after this function returns so the scan can be done asynchronously.
///                             The integrator is responsible of notifying introcore when the buffer is no longer needed
///                             by invoking the notification callback registered with
///                             #GLUE_IFACE.RegisterEnginesResultCallback.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyEngines)(
    _In_ void *GuestHandle,
    _Inout_ void *Parameters
    );

///
/// @brief  Translates a guest physical address to a host physical address.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Gpa             Guest physical address to be translated.
/// @param[out] Hpa             Host physical address at which the GPA is mapped.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGpaToHpa)(
    _In_ void *GuestHandle,
    _In_ QWORD Gpa,
    _Out_ QWORD *Hpa
    );

///
/// @brief  Maps a guest physical address to the host virtual space.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  PhysAddress     The guest physical address that must be mapped.
/// @param[in]  Length          The size of the region that must be mapped, in bytes.
/// @param[in]  Flags           Additional flags. Currently, the only available flag is #IG_PHYSMAP_NO_CACHE.
/// @param[out] HostPtr         A pointer to the pointer that will map the physical memory area.
///                             This pointer must remain valid until introcore calls #GLUE_IFACE.PhysMemUnmap.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntPhysMemMapToHost)(
    _In_ void *GuestHandle,
    _In_ QWORD PhysAddress,
    _In_ DWORD Length,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    );

///
/// @brief  Frees any resources allocated by a #GLUE_IFACE.PhysMemMapToHost call.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in, out] HostPtr     A pointer to the pointer that maps the physical memory previously mapped.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntPhysMemUnmap)(
    _In_ void *GuestHandle,
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    );

///
/// @brief  Returns the memory type of a guest physical page, as taken from the MTRRs.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Gpa             The guest physical address for which the memory type is requested.
/// @param[out] MemType         The memory type of the Gpa.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGetPhysicalPageTypeFromMtrrs)(
    _In_ void *GuestHandle,
    _In_ QWORD Gpa,
    _Out_ IG_MEMTYPE *MemType
    );

///
/// @brief  Returns the EPT access rights for a guest physical page.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  EptIndex        The EPTP index of the EPT for which the query is done. Can be #IG_CURRENT_EPT to signal
///                             that the currently loaded EPT should be used.
/// @param[in]  Address         The guest physical address for which the access rights are requested.
/// @param[out] Read            1 if the page is readable, 0 otherwise. Ignored on unsuccessful calls.
/// @param[out] Write           1 if the page is writable, 0 otherwise. Ignored on unsuccessful calls.
/// @param[out] Execute         1 if the page is executable, 0 otherwise. Ignored on unsuccessful calls.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGetEPTPageProtection)(
    _In_ void *GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    );

///
/// @brief  Sets the EPT access rights for a guest physical page.
///
/// @param[in] GuestHandle  Integrator-specific guest identifier.
/// @param[in] EptIndex     The EPTP index of the EPT for which the query is done. Can be #IG_CURRENT_EPT to signal
///                         that the currently loaded EPT should be used.
/// @param[in] Address      The guest physical address for which the access rights are requested.
/// @param[in] Read         1 if the read permission is granted, 0 if not.
/// @param[in] Write        1 if the write permission is granted, 0 if not.
/// @param[in] Execute      1 if the execute permission is granted, 0 if not.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSetEPTPageProtection)(
    _In_ void *GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BYTE Read,
    _In_ BYTE Write,
    _In_ BYTE Execute
    );

///
/// @brief  Returns the SPP protection rights for a guest physical address. This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Address         The guest physical address for which the query is done.
/// @param[out] SppValue        On success, will contain the SPP table entry for Address.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGetSPPPageProtection)(
    _In_ void *GuestHandle,
    _In_ QWORD Address,
    _Out_ QWORD *SppValue
    );

///
/// @brief  Set the SPP protection rights for a guest physical address. This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Address         The guest physical address for which the query is done.
/// @param[out] SppValue        The SPP table entry for Address.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSetSPPPageProtection)(
    _In_ void *GuestHandle,
    _In_ QWORD Address,
    _In_ QWORD SppValue
    );

///
/// @brief  Registers and EPT exit callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on EPT violation exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterEPTHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntEPTViolationCallback Callback
    );

///
/// @brief  Unregisters the current EPT exit callback, unsubscribing introcore from EPT violation events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterEPTHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Enables VMEXIT events for a MSR.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Msr             The MSR for which the exit is enabled.
/// @param[out] OldValue        True if the exit was already enabled, False otherwise.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntEnableMsrExit)(
    _In_ void *GuestHandle,
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    );

///
/// @brief  Disable VMEXIT events for a MSR.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Msr             The MSR for which the exit is disabled.
/// @param[out] OldValue        True if the exit was enabled before this call, False otherwise.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntDisableMsrExit)(
    _In_ void *GuestHandle,
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    );

///
/// @brief  Registers a MSR exit handler.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on MSR violation exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
/// @remarks    If multiple callbacks are registered, only the last one will be considered valid.
///
typedef INTSTATUS
(*PFUNC_IntRegisterMSRHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntMSRViolationCallback Callback
    );

///
/// @brief  Unregisters the current MSR exit callback, unsubscribing introcore from MSR violation events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterMSRHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers a VMCALL exit handler.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on VMCALL exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterIntroCallHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntIntroCallCallback Callback
    );

///
/// @brief  Unregisters the current VMCALL exit callback, unsubscribing introcore from VMCALL events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterIntroCallHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers a timer callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterVmxTimerHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntIntroTimerCallback Callback
    );

///
/// @brief  Unregisters the current timer callback, unsubscribing introcore from timer events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterVmxTimerHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers a descriptor table access callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on DTR violation exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterDescriptorTableHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntIntroDescriptorTableCallback Callback
    );

///
/// @brief  Unregisters the current descriptor table access callback, unsubscribing introcore from DTR events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterDescriptorTableHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Enables VMEXIT events for a control register.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Cr              The control register for which the exit is enabled.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntEnableCrWriteExit)(
    _In_ void *GuestHandle,
    _In_ DWORD Cr
    );

///
/// @brief  Disable VMEXIT events for a control register.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Cr              The control register for which the exit is disabled.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntDisableCrWriteExit)(
    _In_ void *GuestHandle,
    _In_ DWORD Cr
    );

///
/// @brief  Registers a control register write callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on CR write violation exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterCrWriteHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntCrWriteCallback Callback
    );

///
/// @brief  Unregisters the current control register write callback, unsubscribing introcore from CR events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterCrWriteHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers an extended control register write callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on XCR write violation exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterXcrWriteHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntXcrWriteCallback Callback
    );

///
/// @brief  Unregisters the current extended control register write callback, unsubscribing introcore from XCR events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterXcrWriteHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers a break point event callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked on break point exits.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterBreakpointHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntBreakpointCallback Callback
    );

///
/// @brief  Unregisters the current break point event callback, unsubscribing introcore from BP events.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterBreakpointHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers an event injection callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked when an exception is injected inside the guest.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterEventInjectionHandler)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntEventInjectionCallback Callback
    );

///
/// @brief  Unregisters the current event injection callback.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterEventInjectionHandler)(
    _In_ void *GuestHandle
    );

///
/// @brief  Registers a third party scan result callback. This API is optional.
///
/// If this API is implemented, #PFUNC_IntUnregisterEnginesResultCalback should also be implemented.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Callback        The callback that must be invoked when the third party tools finished a scan.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRegisterEnginesResultCallback)(
    _In_ void *GuestHandle,
    _In_ PFUNC_IntEventEnginesResultCallback Callback
    );

///
/// @brief  Unregisters the current third party scan result callback.
///
/// This API is optional, but it should be implemented if #PFUNC_IntRegisterEnginesResultCallback was implemented.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntUnregisterEnginesResultCalback)(
    _In_ void *GuestHandle
    );

///
/// @brief  Pauses all the VCPUs assigned to a guest.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
/// @remarks    Failures of this API are considered fatal errors by the introspection engine.
///
typedef INTSTATUS
(*PFUNC_IntRequestVcpusPause)(
    _In_ void *GuestHandle
    );

///
/// @brief  Resumes all the VCPUs assigned to a guest that were previously paused with a #GLUE_IFACE.PauseVcpus call.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
/// @remarks    Failures of this API are considered fatal errors by the introspection engine.
///
typedef INTSTATUS
(*PFUNC_IntRequestVcpusResume)(
    _In_ void *GuestHandle
    );

///
/// @brief  Reserves a dedicated memory region inside the hypervisor page tables. This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[out] FirstPageBase   The virtual address of the first virtual address space reserved.
/// @param[out] PagesCount      The number of reserved pages.
/// @param[out] PtBase          Pointer to the base of the page tables.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntReserveVaSpaceWithPt)(
    _In_ void *GuestHandle,
    _Outptr_ void **FirstPageBase,
    _Out_ DWORD *PagesCount,
    _Outptr_ void **PtBase
    );

/// @brief  Injects an exception inside the guest.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The VCPU on which the injection will be done.
/// @param[in]  TrapNumber      The exception number.
/// @param[in]  ErrorCode       The error code, for exceptions that have one.
/// @param[in]  Cr2             For page fault injections, the value of the CR2, ignored for other types.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntInjectTrap)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ BYTE TrapNumber,
    _In_ DWORD ErrorCode,
    _In_opt_ QWORD Cr2
    );

///
/// @brief  Notifies the integrator that the introspection engine detected an operating system.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  GuestInfo       Information about the type and version of the detected operating system.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyIntrospectionDetectedOs)(
    _In_ void *GuestHandle,
    _In_ PGUEST_INFO GuestInfo
    );

///
/// @brief  Notifies the integrator about an error encountered by the introspection engine.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Error           The encountered error.
/// @param[in]  Context         Error specific context. Not all INTRO_ERROR_STATE values have a context. Once this
///                             function returns, the Context pointer is no longer valid.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyIntrospectionErrorState)(
    _In_ void *GuestHandle,
    _In_ INTRO_ERROR_STATE Error,
    _In_opt_ PINTRO_ERROR_CONTEXT Context
    );

///
/// @brief  Notifies the integrator that the introspection engine is active.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyIntrospectionActivated)(
    _In_ void *GuestHandle
    );

///
/// @brief  Notifies the integrator that the introspection engine is no longer active.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntNotifyIntrospectionDeactivated)(
    _In_ void *GuestHandle
    );


///
/// @brief  Sets the memory contents with which an instruction will be emulated by the hypervisor.
///
/// When this function is called, the emulation of the instruction that caused the current VMEXIT should use Buffer
/// contents instead of the real memory contents when emulating accesses in the range [VirtualAddress,
/// VirtualAddress + BufferSize).
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The VCPU number. Can be #IG_CURRENT_VCPU.
/// @param[in]  VirtualAddress  The virtual address for which the Buffer contents will be used. It is important
///                             that the hypervisor uses this address, and not the one reported by the VMEXIT
///                             as they can be different.
/// @param[in]  BufferSize      The size of the buffer, in bytes.
/// @param[in]  Buffer          The emulator context buffer.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSetIntroEmulatorContext)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ QWORD VirtualAddress,
    _In_ DWORD BufferSize,
    _In_reads_bytes_(BufferSize) PBYTE Buffer
    );

///
/// @brief  Gets the content of the agent file. This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  AgentTag        The tag of the agent. See #IG_AGENT_TAG for possible values.
/// @param[in]  Is64            True if the contents will be for a 64-bit agent, False if not.
/// @param[out] Size            The size of the agent contents.
/// @param[out] Content         The pointer to the agent contents.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGetAgentContent)(
    _In_ void *GuestHandle,
    _In_ DWORD AgentTag,
    _In_ BOOLEAN Is64,
    _Out_ DWORD *Size,
    _Outptr_ PBYTE *Content
    );

///
/// @brief  Frees all the resources associated with the given buffer.
///
/// This is primarily used by the CAMI update mechanism to notify the integrator when the CAMI buffer can safely be
/// freed.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Buffer          The buffer to be freed.
/// @param[in]  Size            The size of the buffer.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS (*PFUNC_IntReleaseBuffer)(
    _In_ void *GuestHandle,
    _In_ void *Buffer,
    _In_ DWORD Size
    );

///
/// @brief  Enables or disables the REP optimization.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Enable          True if the optimizations will be enabled, False if not.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntToggleRepOptimization)(
    _In_ void *GuestHandle,
    _In_ BOOLEAN Enable
    );

//
// These functions are exposed by the introspection engine for the HV
//

///
/// @brief  Notifies introcore that the guest must be introspected.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier. The introspection engine treats this as an opaque
///                             value. It will be passed back to the integrator when calling #GLUE_IFACE APIs. It must 
///                             not change while the introspection engine is running.
/// @param[in]  Options         Activation and protection flags. See @ref group_options.
/// @param[in]  UpdateBuffer    The CAMI buffer that will be used by introcore for information about the guest. It
///                             must remain valid until introcore calls GLUE_FACE.ReleaseBuffer.
/// @param[in]  BufferLength    The size of the buffer, in bytes.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if introcore can not introspect this guest because it is transitioning to
///             another power state.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE if the CAMI buffer is not big enough. This usually points to a corruption
///             in the buffer.
/// @retval     #INT_STATUS_INVALID_DATA_TYPE if the CAMI buffer is corrupted.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the CAMI version is not supported.
///
/// @remarks    Note that even if the function exits with success, certain aspects of the initialization are done on
///             VMEXIT events, thus other errors could stop introcore from properly introspecting a guest.
///             #GLUE_IFACE.NotifyIntrospectionErrorState will be used to report such errors.
///
typedef INTSTATUS
(*PFUNC_IntNotifyNewGuest)(
    _In_ void *GuestHandle,
    _In_ QWORD Options,
    _In_reads_(BufferLength) PBYTE UpdateBuffer,
    _In_ DWORD BufferLength
    );

///
/// @brief  Disables the introspection engine.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Flags           Flags that control the disable method. Can be 0 or #IG_DISABLE_IGNORE_SAFENESS.
///
/// @retval     #INT_STATUS_SUCCESS if the operation completed with success.
/// @retval     #INT_STATUS_CANNOT_UNLOAD if introcore can not be disabled at the moment. In these cases the integrator
///             should let the guest run for a while (1 second, for example) and then try to disable introcore again.
///             This status can not be returned if Flags is set to #IG_DISABLE_IGNORE_SAFENESS.
///
/// @remarks    Note that using IG_DISABLE_IGNORE_SAFENESS may put the guest in an unstable state.
///
typedef INTSTATUS
(*PFUNC_IntDisableIntro)(
    _In_ void *GuestHandle,
    _In_ QWORD Flags
    );


///
/// @brief      Loads a new exceptions version.
/// @ingroup    group_exceptions
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Buffer          Buffer with the exception contents. This buffer should remain valid until this function
///                             returns.
/// @param[in]  Length          The size of the buffer, in bytes.
/// @param[in]  Flags           Optional flags that control the update. No such flags exist at the moment.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_INVALID_OBJECT_TYPE if the update buffer is corrupted.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the exceptions version is not supported.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if introcore detected a fatal error during the update.
///
/// @remarks    After a successful call, the previously loaded exceptions are removed. Exceptions loaded with
///             #GLUE_IFACE.AddExceptionFromAlert are not removed.
///
typedef INTSTATUS
(*PFUNC_IntUpdateExceptions)(
    _In_ void *GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
    );

///
/// @brief      Loads a new CAMI version.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Buffer          Buffer with the update contents. This buffer should remain valid until
///                             #GLUE_IFACE.ReleaseBuffer is called.
/// @param[in]  Length          The size of the buffer, in bytes.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE if the CAMI buffer is not big enough. This usually points to a corruption
///             in the buffer.
/// @retval     #INT_STATUS_INVALID_DATA_TYPE if the CAMI buffer is corrupted.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the CAMI version is not supported.
///
/// @remarks    After a successful call, the previously loaded CAMI settings are removed.
///
typedef INTSTATUS
(*PFUNC_IntUpdateSupport)(
    _In_ void *GuestHandle,
    _In_reads_(Length) PBYTE Buffer,
    _In_ DWORD Length
    );

///
/// @brief  Get the current version of CAMI.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[out] MajorVersion    The major version.
/// @param[out] MinorVersion    The minor version.
/// @param[out] BuildNumber     The build number.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetSupportVersion)(
    _In_ void *GuestHandle,
    _Out_ DWORD *MajorVersion,
    _Out_ DWORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    );

///
/// @brief      Get the current exceptions version.
/// @ingroup    group_exceptions
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[out] MajorVersion    The major version.
/// @param[out] MinorVersion    The minor version.
/// @param[out] BuildNumber     The build number.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetExceptionsVersion)(
    _In_ void *GuestHandle,
    _Out_ WORD *Major,
    _Out_ WORD *Minor,
    _Out_ DWORD *BuildNumber
    );

///
/// @brief  Get a description of the introspected guest.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[out] GuestInfo       A pointer to a GUEST_INFO structure that will contain information about the guest.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetGuestInfo)(
    _In_ void *GuestHandle,
    _Out_ PGUEST_INFO GuestInfo
    );

///
/// @brief      Adds an exception for an alert reported by introcore.
/// @ingroup    group_exceptions
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Event           Exception information supplied by introcore on #GLUE_IFACE.NotifyIntrospectionAlert
///                             calls. If Exception is True, this buffer has the contents of the
///                             #INTRO_VIOLATION_HEADER.Exception field. If it is set to False, this buffer should
///                             contains the entire alert.
/// @param[in]  Type            The type of the event.
/// @param[in]  Exception       The type of contents in the buffer.
/// @param[in]  Context         Integrator-specific exception identifier. Can be 0.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the type of event can not be excepted.
/// @retval     #INT_STATUS_INVALID_DATA_STATE if the size of the buffer is not valid.
///
typedef INTSTATUS
(*PFUNC_IntAddExceptionFromAlert)(
    _In_ void *GuestHandle,
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
    );

///
/// @brief      Removes all the custom exceptions added with #GLUE_IFACE.AddExceptionFromAlert.
/// @ingroup    group_exceptions
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntFlushAlertExceptions)(
    _In_ void *GuestHandle
    );

///
/// @brief      Removes a custom exception added with #GLUE_IFACE.AddExceptionFromAlert.
/// @ingroup    group_exceptions
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[in]  Context         The context of the exception that must be removed. All exceptions that share the same
///                             context will be removed.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the guest is already introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntRemoveException)(
    _In_ void *GuestHandle,
    _In_opt_ QWORD Context
    );

///
/// @brief  Toggles protection for a process
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  FullPath        The name or the full path of the process.
/// @param[in]  ProtectionMask  Protection flags. A combination of the @ref group_process_options values. Ignored if
///                             Add is False.
/// @param[in]  Add             True if the process should be protected, False if the protection should be removed.
/// @param[in]  Context         Integrator-specific context that will be passed back by introcore when sending
///                             notifications related tot his process.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
////            to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the introspection engine is preparing to unload.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if an identical protection policy already exists.
///
typedef INTSTATUS
(*PFUNC_IntAddRemoveProtectedProcessUtf16)(
    _In_ void *GuestHandle,
    _In_z_ const WCHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    );

///
/// @brief  Toggles protection for a process.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  FullPath        The name or the full path of the process.
/// @param[in]  ProtectionMask  Protection flags. A combination of the @ref group_process_options values. Ignored if
///                             Add is False.
/// @param[in]  Add             True if the process should be protected, False if the protection should be removed.
/// @param[in]  Context         Integrator-specific context that will be passed back by introcore when sending
///                             notifications related tot his process.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the introspection engine is preparing to unload.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if an identical protection policy already exists.
///
typedef INTSTATUS
(*PFUNC_IntAddRemoveProtectedProcessUtf8)(
    _In_ void *GuestHandle,
    _In_z_ const CHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    );

///
/// @brief  Abort the introcore loading process.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.

typedef INTSTATUS (*PFUNC_IntSetIntroAbortStatus)(
    _In_ void *GuestHandle,
    _In_ BOOLEAN Abort
    );

///
/// @brief  Removes the protection policies for all processes.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the introspection engine is preparing to unload.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if an identical protection policy already exists.
///
typedef INTSTATUS
(*PFUNC_IntRemoveAllProtectedProcesses)(
    _In_ void *GuestHandle
    );

///
/// @brief  Notifies introcore about a guest power state change.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  PowerState      The power state to which the guest is transitioning.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
typedef INTSTATUS
(*PFUNC_IntNotifyGuestPowerStateChange)(
    _In_ void *GuestHandle,
    _In_ IG_GUEST_POWER_STATE PowerState
    );

#define IG_MAX_COMMAND_LINE_LENGTH  1024
#define IG_MAX_AGENT_NAME_LENGTH    32

///
/// @brief  Requests a process agent injection inside the guest.
///
/// This function will create a new process inside the guest, running the executable provided by the integrator.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  AgentTag        The tag of the agent.
/// @param[in]  AgentContent    The contents of the agent. If AgentTag is not #IG_AGENT_TAG_CUSTOM_TOOL this buffer
///                             can not be NULL.
/// @param[in]  AgentSize       The size of the AgentContent buffer, in bytes.
/// @param[in]  Name            A NULL-terminated string that contains the name the process will have inside the guest.
/// @param[in]  Args            A NULL-terminated string containing the arguments that will be passed to the process.
///                             Can be NULL.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the introspection engine is preparing to unload.
/// @retval     #INT_STATUS_UNINIT_BUGCHECK if introcore is unloading as a result of a guest crash.
///
typedef INTSTATUS
(*PFUNC_IntInjectProcessAgent)(
    _In_ void *GuestHandle,
    _In_ DWORD AgentTag,
    _In_opt_ PBYTE AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_z_ const CHAR *Name,
    _In_opt_z_ const CHAR *Args
    );

///
/// @brief  Drops a file on the guest hard disk.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  FileContent     The contents of the file.
/// @param[in]  FileSize        The size of the file, in bytes.
/// @param[in]  Name            A NULL-terminated string containing the name of the file.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the introspection engine is preparing to unload.
/// @retval     #INT_STATUS_UNINIT_BUGCHECK if introcore is unloading as a result of a guest crash.
///
typedef INTSTATUS
(*PFUNC_IntInjectFileAgent)(
    _In_ void *GuestHandle,
    _In_opt_ PBYTE FileContent,
    _In_ DWORD FileSize,
    _In_z_ const CHAR *Name
    );

///
/// @brief  Returns the length of the instruction at which the current guest RIP points.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The VCPU for which the query is done. This can not be #IG_CURRENT_VCPU.
/// @param[out] Length          The length of the instruction.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetCurrentInstructionLength)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ BYTE *Length
    );

///
/// @brief  Returns the mnemonic of the instruction at which the current guest RIP points.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The VCPU for which the query is done. This can not be #IG_CURRENT_VCPU.
/// @param[out] Mnemonic        NULL-terminated string containing the mnemonic. This buffer should have a size of at
///                             least ND_MAX_MNEMONIC_LENGTH.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetCurrentInstructionMnemonic)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ CHAR *Mnemonic
    );

///
/// @brief  The type of callback invoked by #PFUNC_IntIterateVaSpace while iterating the guest virtual address space.
///
/// @param[in]  Cr3             The guest CR3 that describes the address space over which to iterate.
/// @param[in]  VirtualAddress  The guest virtual address of the current page.
/// @param[in]  Entry           The page table entry that maps VirtualAddress.
/// @param[in]  PageSize        The size of the page that maps VirtualAddress.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_VirtualAddressSpaceCallback)(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD Entry,
    _In_ QWORD PageSize
    );

///
/// @brief  Iterates over the guest virtual address space.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  Cr3             The guest CR3 that describes the address space over which to iterate.
/// @param[in]  Callback        Callback that will be invoked for every valid page.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntIterateVaSpace)(
    _In_ void *GuestHandle,
    _In_ QWORD Cr3,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    );

///
/// @brief  Modifies the introcore options.
///
/// @param[in]  GuestHandle         Integrator-specific guest identifier.
/// @param[in]  NewDynamicOptions   The new options. These are a combination of @ref group_options values.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntModifyDynamicOptions)(
    _In_ void *GuestHandle,
    _In_ QWORD NewDynamicOptions
    );

///
/// @brief  Flushed the introcore GPA cache.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if there is no active GPA cache.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntFlushGpaCache)(
    _In_ void *GuestHandle
    );

///
/// @brief  Get the currently used introcore options.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier
/// @param[out] IntroOptions    The options that are used. Will be a combination of @ref group_options values.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED if no guest is currently introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
///
typedef INTSTATUS
(*PFUNC_IntGetCurrentIntroOptions)(
    _In_  void *GuestHandle,
    _Out_ QWORD *IntroOptions
    );

///
/// @brief  Sets the log level.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  LogLevel        The new log level.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
typedef INTSTATUS
(*PFUNC_IntSetLogLevel)(
    _In_ void *GuestHandle,
    _In_ IG_LOG_LEVEL LogLevel
    );

///
/// @brief  Get the version string information for the current guest.
///
/// @param[in]  FullStringSize      The size, in bytes, of the FullString buffer, including the NULL terminator.
/// @param[in]  VersionStringSize   The size, in bytes, of the VersionString buffer, including the NULL terminator.
/// @param[out] FullString          A NULL-terminated string containing detailed version information.
/// @param[out] VersionString       A NULL-terminated string containing human-readable version information.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_INITIALIZED if no guest is currently introspected.
/// @retval     #INT_STATUS_POWER_STATE_BLOCK if the operation can not be completed because the guest is transitioning
///             to another power state.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL if one or both of the buffers are not large enough.
///
typedef INTSTATUS
(*PFUNC_IntGetVersionString)(
      _In_  DWORD FullStringSize,
      _In_  DWORD VersionStringSize,
      _Out_ CHAR *FullString,
      _Out_ CHAR *VersionString
      );


//
// Debug facilities
//

///
/// @brief  Executes a debugger command.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The current VCPU number.
/// @param[in]  Argc            The number of arguments.
/// @param[in]  Argv            An array of NULL terminated strings.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
typedef INTSTATUS
(*PFUNC_IntDebugProcessCommand)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ DWORD Argc,
    _In_ CHAR *Argv[]
    );


//
// #VE related API, exposed by the integrator
//

///
/// @brief  Set the Virtualization exception info page.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The VCPU Number for which the setting is done.
/// @param[in]  VeInfoGpa       The guest physical address at which the info page resides.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSetVeInfoPage)(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoGpa
    );

///
/// @brief  Creates a new EPT.
///
/// This API is optional
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[out] EptIndex        The EPTP index for the newly created EPT.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntCreateEPT)(
    _In_ void *GuestHandle,
    _Out_ DWORD *EptIndex
    );

///
/// @brief  Destroys an EPT.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  EptIndex        The EPTP index of the EPT that will be deleted.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntDestroyEPT)(
    _In_ void *GuestHandle,
    _In_ DWORD EptIndex
    );

///
/// @brief  Switches the currently loaded EPT.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  EptIndex        The index of the EPT that will be loaded.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSwitchEPT)(
    _In_ void *GuestHandle,
    _In_ DWORD NewEptIndex
    );

///
/// @brief  Get the convertible status of a guest physical page.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  EptIndex        The index of the EPT for which the query is done. Can be #IG_CURRENT_EPT.
/// @param[in]  Address         The guest physical address for which the query is done.
/// @param[out] Convertible     True if the page is convertible, False if it is not.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntGetEPTPageConvertible)(
    _In_ void *GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BOOLEAN *Convertible
    );

///
/// @brief  Set the convertible status of a guest physical page.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  EptIndex        The index of the EPT for which the query is done. Can be #IG_CURRENT_EPT.
/// @param[in]  Address         The guest physical address for which the query is done.
/// @param[in] Convertible      True if the page will be made convertible, False if it will be made not convertible.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSetEPTPageConvertible)(
    _In_ void *GuestHandle,
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BOOLEAN Convertible
    );


///
/// @brief Flushes the EPT access permissions. Once this function returns, the caller can be assured that all
/// modifications made to the EPT ar globally visible for the guest.
///
/// This API is optional.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntFlushEPTPermissions)(
    _In_ void* GuestHandle
    );

///
/// @brief  Interface used for communicating between the introspection engine and the integrator.
///
/// Before using any of the function pointers in the structure, it must be validated using the #GLUE_IFACE.Version and
/// #GLUE_IFACE.Size fields in order to ensure that the introcore version used matches the one for which this header
/// file was published.
///
/// Documentation for each function from the interface is found on the documentation for that specific function pointer.
///
typedef struct _GLUE_IFACE
{
    /// The version of the interface. Must match #GLUE_IFACE_VERSION_1.
    DWORD                                       Version;
    /// The size of the interface.Must match #GLUE_IFACE_VERSION_1_SIZE.
    DWORD                                       Size;
    QWORD                                       Reserved;

    //
    // following functions have semantics of introspection library -> hypervisor
    //

    PFUNC_IntQueryGuestInfo                     QueryGuestInfo;

    PFUNC_IntGpaToHpa                           GpaToHpa;

    PFUNC_IntPhysMemMapToHost                   PhysMemMapToHost;
    PFUNC_IntPhysMemUnmap                       PhysMemUnmap;
    PFUNC_IntGetPhysicalPageTypeFromMtrrs       PhysMemGetTypeFromMtrrs;

    PFUNC_IntGetEPTPageProtection               GetEPTPageProtection;
    PFUNC_IntSetEPTPageProtection               SetEPTPageProtection;
    PFUNC_IntGetSPPPageProtection               GetSPPPageProtection;
    PFUNC_IntSetSPPPageProtection               SetSPPPageProtection;
    PFUNC_IntRegisterEPTHandler                 RegisterEPTHandler;
    PFUNC_IntUnregisterEPTHandler               UnregisterEPTHandler;

    PFUNC_IntEnableMsrExit                      EnableMSRExit;
    PFUNC_IntDisableMsrExit                     DisableMSRExit;
    PFUNC_IntRegisterMSRHandler                 RegisterMSRHandler;
    PFUNC_IntUnregisterMSRHandler               UnregisterMSRHandler;

    PFUNC_IntRequestVcpusPause                  PauseVcpus;
    PFUNC_IntRequestVcpusResume                 ResumeVcpus;

    // VMCALL handler for introspection specific calls.
    PFUNC_IntRegisterIntroCallHandler           RegisterIntroCallHandler;
    PFUNC_IntUnregisterIntroCallHandler         UnregisterIntroCallHandler;

    // VMX-Preemption timer callback - allows to do periodic stuff, like integrity checking.
    PFUNC_IntRegisterVmxTimerHandler            RegisterIntroTimerHandler;
    PFUNC_IntUnregisterVmxTimerHandler          UnregisterIntroTimerHandler;

    // GDTR/IDTR access
    PFUNC_IntRegisterDescriptorTableHandler     RegisterDtrHandler;
    PFUNC_IntUnregisterDescriptorTableHandler   UnregisterDtrHandler;

    PFUNC_IntEnableCrWriteExit                  EnableCrWriteExit;
    PFUNC_IntDisableCrWriteExit                 DisableCrWriteExit;
    PFUNC_IntRegisterCrWriteHandler             RegisterCrWriteHandler;
    PFUNC_IntUnregisterCrWriteHandler           UnregisterCrWriteHandler;

    // XCR write handler.
    PFUNC_IntRegisterXcrWriteHandler            RegisterXcrWriteHandler;
    PFUNC_IntUnregisterXcrWriteHandler          UnregisterXcrWriteHandler;

    // Breakpoint handler.
    PFUNC_IntRegisterBreakpointHandler          RegisterBreakpointHandler;
    PFUNC_IntUnregisterBreakpointHandler        UnregisterBreakpointHandler;

    // Event injection handler.
    PFUNC_IntRegisterEventInjectionHandler      RegisterEventInjectionHandler;
    PFUNC_IntUnregisterEventInjectionHandler    UnregisterEventInjectionHandler;

    PFUNC_IntInjectTrap                         InjectTrap;

    PFUNC_IntSetIntroEmulatorContext            SetIntroEmulatorContext;

    //
    // From here on, these functions are optional (until HV - Intro interface)
    //

    PFUNC_IntReserveVaSpaceWithPt               ReserveVaSpaceWithPt;

    PFUNC_IntNotifyIntrospectionActivated       NotifyIntrospectionActivated;
    PFUNC_IntNotifyIntrospectionDeactivated     NotifyIntrospectionDeactivated;
    PFUNC_IntNotifyIntrospectionDetectedOs      NotifyIntrospectionDetectedOs;
    void                                        *_I_H_Reserved1;
    PFUNC_IntNotifyIntrospectionErrorState      NotifyIntrospectionErrorState;
    PFUNC_IntNotifyIntroAlert                   NotifyIntrospectionAlert;
    PFUNC_IntNotifyEngines                      NotifyScanEngines;

    PFUNC_IntGetAgentContent                    GetAgentContent;
    PFUNC_IntReleaseBuffer                      ReleaseBuffer;
    PFUNC_IntToggleRepOptimization              ToggleRepOptimization;

    //
    // #VE related API (Optional)
    //
    PFUNC_IntSetVeInfoPage                      SetVeInfoPage;
    PFUNC_IntCreateEPT                          CreateEPT;
    PFUNC_IntDestroyEPT                         DestroyEPT;
    PFUNC_IntSwitchEPT                          SwitchEPT;
    PFUNC_IntGetEPTPageConvertible              GetEPTPageConvertible;
    PFUNC_IntSetEPTPageConvertible              SetEPTPageConvertible;

    // Asynchronous callback used by the engines to provide a scan result.
    PFUNC_IntRegisterEnginesResultCallback      RegisterEnginesResultCallback;
    PFUNC_IntUnregisterEnginesResultCalback     UnregisterEnginesResultCalback;

    PFUNC_IntFlushEPTPermissions                FlushEPTPermissions;

    void                                        *_I_H_Reserved2;
    void                                        *_I_H_Reserved3;

    //
    // following functions have semantics of hypervisor -> introspection library.
    // the below function pointers must be populated by the introspection library at initialization
    // the hypervisor expects that, if IntInit was successful, the below pointers are valid
    //
    PFUNC_IntNotifyNewGuest                     NewGuestNotification;
    PFUNC_IntDisableIntro                       DisableIntro;
    PFUNC_IntNotifyGuestPowerStateChange        NotifyGuestPowerStateChange;

    PFUNC_IntDebugProcessCommand                DebugProcessCommand;
    void                                        *_H_I_Reserved1;
    PFUNC_IntUpdateExceptions                   UpdateExceptions;
    PFUNC_IntGetExceptionsVersion               GetExceptionsVersion;
    PFUNC_IntGetGuestInfo                       GetGuestInfo;
    PFUNC_IntInjectProcessAgent                 InjectProcessAgent;
    PFUNC_IntInjectFileAgent                    InjectFileAgent;
    PFUNC_IntSetIntroAbortStatus                SetIntroAbortStatus;
    PFUNC_IntAddExceptionFromAlert              AddExceptionFromAlert;
    PFUNC_IntRemoveException                    RemoveException;
    PFUNC_IntFlushAlertExceptions               FlushAlertExceptions;
    PFUNC_IntAddRemoveProtectedProcessUtf16     AddRemoveProtectedProcessUtf16;
    PFUNC_IntAddRemoveProtectedProcessUtf8      AddRemoveProtectedProcessUtf8;
    PFUNC_IntRemoveAllProtectedProcesses        RemoveAllProtectedProcesses;
    PFUNC_IntGetCurrentInstructionLength        GetCurrentInstructionLength;
    PFUNC_IntGetCurrentInstructionMnemonic      GetCurrentInstructionMnemonic;
    PFUNC_IntIterateVaSpace                     IterateVirtualAddressSpace;
    PFUNC_IntModifyDynamicOptions               ModifyDynamicOptions;
    PFUNC_IntFlushGpaCache                      FlushGpaCache;
    PFUNC_IntGetCurrentIntroOptions             GetCurrentIntroOptions;
    PFUNC_IntUpdateSupport                      UpdateSupport;
    PFUNC_IntGetSupportVersion                  GetSupportVersion;

    PFUNC_IntSetLogLevel                        SetLogLevel;

    PFUNC_IntGetVersionString                   GetVersionString;
    void                                        *_H_I_Reserved2;
    void                                        *_H_I_Reserved3;
    void                                        *_H_I_Reserved4;

} GLUE_IFACE, *PGLUE_IFACE;

#define GLUE_IFACE_VERSION_1            0x00010111
#define GLUE_IFACE_VERSION_1_SIZE       sizeof(GLUE_IFACE)

#define GLUE_IFACE_VERSION_LATEST       GLUE_IFACE_VERSION_1
#define GLUE_IFACE_VERSION_LATEST_SIZE  GLUE_IFACE_VERSION_1_SIZE


//
// The following functions are NOT directly part of the interface, but needs to be
// implemented by any GLUE library (NAPOCA, VMWARE, CITRIX, and so on)
//

typedef void
(*PFUNC_IntPreinit)(
    void
    );

typedef INTSTATUS
(*PFUNC_IntInit)(
    _In_ PGLUE_IFACE GlueInterface,
    _In_ PUPPER_IFACE UpperInterface
    );

typedef INTSTATUS
(*PFUNC_IntUninit)(
    void
    );

typedef BOOLEAN
(*PFUNC_IntCheckCompatibility)(
    _In_ DWORD IntegratorMajor,
    _In_ DWORD IntegratorMinor,
    _In_ DWORD IntegratorRevision,
    _In_ DWORD IntegratorBuild,
    _Out_ DWORD *IntroMajor,
    _Out_ DWORD *IntroMinor,
    _Out_ DWORD *IntroRevision,
    _Out_ DWORD *IntroBuild,
    _In_ DWORD Reserved
    );

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif // _GLUEIFACE_H_
