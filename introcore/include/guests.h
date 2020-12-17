/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GUESTS_H_
#define _GUESTS_H_

#include "winguest.h"
#include "lixguest.h"
#include "bddisasm.h"
#include "bdshemu.h"
#include "vecommon.h"
#include "udlist.h"

///
/// @brief  The various states in which a VCPU can be.
///
typedef enum
{
    CPU_STATE_NONE = 0x00,            ///< No state.
    CPU_STATE_ACTIVE = 0x01,          ///< Up & running.
    CPU_STATE_EPT_VIOLATION = 0x02,   ///< Handling EPT violation.
    CPU_STATE_MSR_VIOLATION = 0x03,   ///< Handling MSR violation.
    CPU_STATE_VMCALL = 0x04,          ///< Handling a VMCALL.
    CPU_STATE_CR_WRITE = 0x05,        ///< Handling a CR load.
    CPU_STATE_DTR_LOAD = 0x06,        ///< Handling a LIDT or LGDT.
    CPU_STATE_TIMER = 0x07,           ///< Handling a timer event.
    CPU_STATE_XCR_WRITE = 0x08,       ///< Handling XSETBV.
    CPU_STATE_BREAKPOINT = 0x09,      ///< Handling a breakpoint (int3).
    CPU_STATE_EVENT_INJECTION = 0x0A, ///< Handling an event injection.
} CPU_STATE;

///
/// @brief      Contains information about the patch buffer.
///
/// This is the buffer used by #GLUE_IFACE.SetIntroEmulatorContext.
///
typedef struct _PATCH_BUFFER
{
    QWORD   Gla;                        ///< The guest linear address for which the buffer is filled.
    DWORD   Size;                       ///< The valid size of the Data buffer.
    BOOLEAN Valid;                      ///< True if Data is valid, False if it is not.
    BYTE    Data[ND_MAX_REGISTER_SIZE]; ///< The actual contents of the buffer.
} PATCH_BUFFER, *PPATCH_BUFFER;

///
/// @brief      Contains information about the buffer used to emulate page table writes.
///
typedef struct _PTEMU_BUFFER
{
    QWORD   Old;        ///< The old, original, value of the written page table entry.
    QWORD   New;        ///< The new, to be written, value of the page table entry.
    BOOLEAN Valid;      ///< True if the information in this structure is valid; False it it is not.
    BOOLEAN Emulated;   ///< True if the access was already emulated; False if it was not emulated.
    BOOLEAN Partial;    ///< True if the write is partial and not the entire page table entry is modified.
} PTEMU_BUFFER, *PPTEMU_BUFFER;


///
/// @brief Will contain the last successfully written page-table entry. This will be used by newly placed hooks
/// on page-table entries that were just written during this exit. If we are dealing with a PAE entry, this structure
/// will be initialized only after the entire 8 bytes entry has been written.
///
typedef struct _PTWRITE_CACHE
{
    QWORD   PteAddress;
    QWORD   Value;
    BOOLEAN Valid;
} PTWRITE_CACHE, *PPTWRITE_CACHE;


#define SHEMU_SHELLCODE_SIZE   0x2000 ///< The shell code buffer size. It should be at least 2 pages in size.
#define SHEMU_STACK_SIZE       0x2000 ///< The size of the stack buffer used by shemu.
#define SHEMU_MAX_INSTRUCTIONS 256    ///< The maximum instructions to be emulated by shemu.

//
// Per-CPU state structure.
//

///
/// @brief  Structure encapsulating VCPU-specific information.
///
typedef struct _VCPU_STATE
{
    /// @brief  The current instruction, pointed by the guest RIP
    ///
    /// It is valid only for EPT exits
    INSTRUX         Instruction;
    /// @brief  The current state of the guest registers
    ///
    /// These are filled on every exit and are updated after every #IntSetGprs.
    /// For #IntGetGprs, #IntRipRead, #IntCr0Read, #IntCr3Read, #IntCr4Read, and #IntCr8Read calls done for the
    /// current VCPU while #gEventId matches #VCPU_STATE.EventId, the values cached here are returned, if they were
    /// previously obtained for this exit.
    IG_ARCH_REGS    Regs;
    QWORD           Ia32Efer;   ///< The value of the guest IA32 EFER MSR
    QWORD           EventId;    ///< EventId for which #VCPU_STATE.Regs is valid
    QWORD           ExitGpa;    ///< The accessed guest physical address, for which the EPT violation was generated.
    QWORD           ExitGla;    ///< The accessed guest linear address, for which the EPT violation was generated.
    QWORD           ExitAccess; ///< The access type for which the EPT violation was generated.
    QWORD           Gpa;        ///< The accessed guest physical address. Valid only for EPT exits
    QWORD           Gla;        ///< The accessed guest virtual address. Valid only for EPT exits
    DWORD           AccessSize; ///< The size of the memory access. Valid only for EPT exits

    /// @brief  The guest linear address of the _KPCR structure loaded by this CPU
    ///
    /// Valid only for Windows guests.
    QWORD           PcrGla;

    QWORD           IdtBase;    ///< Original IDT base
    WORD            IdtLimit;   ///< The current IDT limit
    QWORD           GdtBase;    ///< Original GDT base

    QWORD           Xcr0;       ///< The value of XCR0. Updated by #IntHandleXcrWrite

    /// @brief  The currently pending \#UD injection on this CPU
    ///
    /// Since we can't be sure if and when an \#UD injection will succeed, we remember here the one we wait for
    /// on this VCPU. There can not be more than one pending injection for one VCPU at a time. If it is NULL, there
    /// is no pending injection on this VCPU.
    /// Ca be set by #IntWinVadHandlePageExecution and #IntLixVmaHandlePageExecution and reset by
    /// #IntHandleEventInjection and #IntUDRemoveAllEntriesForCr3.
    INFO_UD_PENDING *CurrentUD;

    /// @brief  The exception to be injected in guest
    struct
    {
        /// @brief  True if the fields are valid; False if they are not
        ///
        /// When it is True, an exception was injected using #IntInjectTrap. It is set to True by
        /// #IntInjectExceptionInGuest and reset to False in #IntHandleEventInjection
        BOOLEAN     Valid;
        BYTE        Vector;     ///< The injected exception number
        DWORD       ErrorCode;  ///< The error code, for exceptions that have an error code
        QWORD       Cr2;        ///< The Cr2. Valid only if Vector is 14 (Page Fault)
    } Exception;

    /// @brief  The IDT protection object
    ///
    /// These are both void* so they need to be casted to the appropriate object anyway. They have different names to
    /// point out that sometimes this is either a hook object (when the IDT is protected with an EPT hook) or a
    /// integrity region.
    /// For Windows guests, the decision of the protection type is done in #IntWinIdtProtectOnCpu based on the OS
    /// type and version. For 64-bit Windows versions starting with version 16299, the EPT protection is used; we
    /// can do this because the IDT is in its own dedicated page. For the other Windows version the integrity
    /// protection is used. We do this because on those versions, the IDT is in a page that is written quite often
    /// by the OS, and placing an EPT hook on it will bring a performance impact.
    /// On Linux, the EPT protection is always used as the IDT is always in its own page.
    union
    {
        /// @brief  The EPT hook object used to protect the IDT
        ///
        /// Created in #IntWinIdtProtectOnCpuEpt for Windows guests and #IntLixIdtProtectOnCpu for Linux guests.
        /// Freed in #IntWinIdtUnprotectOnCpuEpt and #IntLixIdtUnprotectAll.
        void        *IdtHookObject;
        /// @brief  The integrity region used to protect the IDT
        ///
        /// Created in #IntWinIdtProtectOnCpuIntegrity and freed in #IntWinIdtUnprotectOnCpuIntergity.
        void        *IdtIntegrityObject;
    };

    // TBD - Add any other VCPU-specific field here.

    /// @brief  The guest virtual address of the running task on the current vCPU
    /// (valid only for Linux / thread safeness)
    QWORD           LixProcessGva;

    PATCH_BUFFER    PatchBuffer;    ///< The patch buffer used to emulate reads
    PTEMU_BUFFER    PtEmuBuffer;    ///< The page table write emulator buffer
    PTWRITE_CACHE   PtWriteCache;   ///< The last written PT entry.

    DWORD           Index;          ///< The VCPU number
    CPU_STATE       State;          ///< The state of this VCPU. Describes what action is the VCPU currently doing

    /// @brief  Set to True if we are in the context of a PT filter VMCALL.
    ///
    /// This can happen if the PT filter issues a VMCALL which is further dispatched using #IntDispatchPtAsEpt.
    BOOLEAN         PtContext;

    /// @brief  Set to True if we are in the context of the \#VE agent.
    ///
    /// This can happen if the agent issues a VMCALL and #IntVeHandleHypercall returns #INT_STATUS_RAISE_EPT. Toggled
    /// by #IntDispatchVeAsEpt while handling the memory access.
    BOOLEAN         VeContext;
    /// @brief  Pointer to the VEINFO page used for this VCPU
    ///
    /// This maps the guest physical address at which the VEINFO page is found, essentially sharing the page
    /// between introcore and the guest. Set to NULL if \#VE is not used.
    /// #IntVeSetVeInfoPage is used to map and unmap it.
    PVECPU          VeInfoPage;
    /// @brief  The index of the current loaded EPT
    ///
    /// Set in #IntHandleEptViolation by using #IntGetCurrentEptIndex. In cases in which a VMCALL issued by the \#VE
    /// agent is dispatched as an EPT violation (#VCPU_STATE.VeContext is set to True), its value is forcibly set to
    /// 0 (the default EPT view).
    DWORD           EptpIndex;

    BOOLEAN         RepOptDisabled; ///< The state of the rep optimization feature
    BOOLEAN         Initialized;    ///< True if the VCPU is initialized and used by the guest, False if it is not
    BOOLEAN         SingleStep;     ///< True if th VCPU is currently single-stepping the current instruction.
    BOOLEAN         AllowOnExec;    ///< True if we returned introGuestAllowed on an execution alert.
    QWORD           AllowOnExecRip; ///< The RIP which was allowed to execute on an exec violation.
    QWORD           AllowOnExecGpa; ///< The GPA which was allowed to execute on an exec violation.
} VCPU_STATE, *PVCPU_STATE;

///
/// @brief  Memory information structure.
///
typedef struct _MM
{
    QWORD       SystemCr3;    ///< The Cr3 used to map the kernel.
    QWORD       Cr4;            ///< Cr4 value used when deducing the paging mode.
    QWORD       Cr0;            ///< Cr0 value used when deducing the paging mode.
    QWORD       Efer;           ///< The value of the IA32 EFER MSR used when deducing the paging mode.
    /// @brief The upper limit of the guest physical address range.
    ///
    /// The physical address range that the guest can access is thus [0, LastGPa - 1] (inclusive).
    /// Note that gaps may be present inside this range.
    QWORD       LastGpa;
    DWORD       SelfMapIndex;   ///< The self map index.
    PAGING_MODE Mode;           ///< The paging mode used by the guest.
} MM, *PMM;

/// @brief  Describes options for this guest.
/// 
/// Every field in this structure must be a combination of @ref group_options values.
typedef struct _INTRO_PROT_OPTIONS
{
    /// @brief  The original options as received from #GLUE_IFACE.NewGuestNotification. This is updated
    /// when #GLUE_IFACE.ModifyDynamicOptions is used
    QWORD Original;
    /// @brief  The currently used options
    ///
    /// These are the #Original flags, but introcore may decide to disable some of them. For example, if both
    /// #INTRO_OPT_IN_GUEST_PT_FILTER and #INTRO_OPT_VE are provided, one of them will be disabled.
    QWORD Current;

    /// @brief  Options that are forcibly disabled
    ///
    /// This can be done by the CAMI mechanism. These are the CAMI_PROT_OPTIONS.ForceOff options. This allows us
    /// to disable problematic options, overriding a protection policy.
    QWORD ForceOff;
    /// @brief  Options that were forced to beta (log-only) mode
    ///
    /// This can be done by the CAMI mechanism. These are the CAMI_PROT_OPTIONS.ForceBeta options. Detections
    /// triggered by the protection mechanism enabled by these flags will never block, the action taken will
    /// always be #introGuestAllowed, and an alert will be generated.
    QWORD Beta;
    /// @brief  Options that will be forced to feedback only mode
    ///
    /// This can be done by the CAMI mechanism. These are the CAMI_PROT_OPTIONS.ForceFeedback options. Detections
    /// triggered by the protection mechanism enabled by these flags will never block, the action taken will
    /// always be #introGuestAllowed, an alert will be generated, but it will have the #ALERT_FLAG_FEEDBACK_ONLY;
    /// the user will not be notified, the event will generate feedback.
    QWORD Feedback;
} INTRO_PROT_OPTIONS;

// Forward these declarations, makes it easy to use it directly when needed
typedef struct _MSR_HOOK_STATE MSR_HOOK_STATE;
typedef struct _XCR_HOOK_STATE XCR_HOOK_STATE;
typedef struct _CR_HOOK_STATE CR_HOOK_STATE;
typedef struct _DTR_HOOK_STATE DTR_HOOK_STATE;
typedef struct _KERNEL_DRIVER KERNEL_DRIVER;
typedef struct _EXCEPTIONS EXCEPTIONS;

///
/// @brief  Describes a guest
///
typedef struct _GUEST_STATE
{
    INTRO_PROT_OPTIONS CoreOptions;     ///< The activation and protection options for this guest.
    INTRO_PROT_OPTIONS ShemuOptions;    ///< Flags which describe the way shemu will give detections.

    QWORD TimerCalls; ///< The number of times the timer callback has been invoked.

    QWORD TscSpeed; ///< Number of ticks/second of this given guest. Should be the same as the global (physical) one.

    INTRO_GUEST_TYPE OSType; ///< The type of the guest.
    DWORD CpuCount;          ///< The number of logical CPUs.
    DWORD ActiveCpuCount;    ///< The number of CPUs actually used by the guest.
    DWORD OSVersion;         ///< Os version.

    QWORD KernelVa;   ///< The guest virtual address at which the kernel image.
    DWORD KernelSize; ///< The size of the kernel.

    /// @brief  True if this structure was initialized and can be used.
    ///
    /// Set in #IntGuestInit and unset in #IntGuestUninit.
    BOOLEAN Initialized;
    BOOLEAN Guest64;             ///< True if this is a 64-bit guest, False if it is a 32-bit guest.
    BOOLEAN KptiActive;          ///< True if KPTI is enabled on this guest, False if it is not.
    BOOLEAN KptiInstalled;       ///< True if KPTI was detected as installed (not necessarily active).
    BOOLEAN GuestInitialized;    ///< True if the OS-specific portion has been initialized.
    BOOLEAN SafeToApplyOptions;  ///< True if the current options can be changed dynamically.
    BOOLEAN PaeEnabled;          ///< True if Physical Address Extension is enabled.
    BOOLEAN LA57;                ///< True if 5-level paging is being used.
    BOOLEAN ProtectionActivated; ///< True if protection was activated for this guest.
    /// @brief  True if the kernel protection is in beta (log-only) mode.
    ///
    /// If this is True, kernel alerts will be generated, but the action will always be #introGuestAllowed.
    /// Set to True when the #INTRO_OPT_KM_BETA_DETECTIONS is passed to #GLUE_IFACE.NewGuestNotification or
    /// #GLUE_IFACE.ModifyDynamicOptions.
    BOOLEAN KernelBetaDetections;
    BOOLEAN SysprocBetaDetections;
    /// @brief  True if the system process protection is in beta (log-only) mode.
    ///
    /// Since the system processes are protected when the #INTRO_OPT_PROT_UM_SYS_PROCS introcore option is used and
    /// no actual process protection policy is received via #GLUE_IFACE.AddRemoveProtectedProcessUtf16 or
    /// #GLUE_IFACE.AddRemoveProtectedProcessUtf8, there is no way of letting an integrator set the
    /// #PROC_OPT_BETA process option for them. In this case, there is an introcore option that can be used:
    /// #INTRO_OPT_SYSPROC_BETA_DETECTIONS.
    /// If this is True, alerts on system processes will be generated, but the action will always be #introGuestAllowed.
    BOOLEAN ShutDown;    ///< The guest has been shut-down. It is no longer safe to access the guest state.
    BOOLEAN Terminating; ///< The guest is terminating.
    /// @brief  True if the guest is entering into hibernate.
    ///
    /// If this is True, most API calls will fail with #INT_STATUS_POWER_STATE_BLOCK as there is no longer safe to
    /// make changes to the guest or the internal introcore state.
    BOOLEAN EnterHibernate;
    BOOLEAN UninitPrepared; ///< True if uninit is prepared.
    /// @brief  Set to True if after returning from this event handler, introcore must be unloaded.
    ///
    /// When certain errors are encountered (for example, failing to find a kernel object during initialization),
    /// introcore must stop and unload, but it can not do that because certain steps of the unload process may
    /// need to let the guest run before completing. In order to avoid these complications, this is set to True
    /// when a reason to disable introcore exists. Event handlers will check it before returning, and if it is
    /// set, the #INT_STATUS_FATAL_ERROR status will be returned.
    BOOLEAN DisableOnReturn;
    /// @brief  True if the slack space for the bootstrap agent has been allocated.
    ///
    /// Set by #IntWinAgentSelectBootstrapAddress and reset by #IntWinAgentReleaseBootstrapAddress.
    BOOLEAN BootstrapAgentAllocated;
    BOOLEAN BugCheckInProgress; ///< Set to True if the guest is in the process of crashing (BSOD/panic).
    /// @brief  If True, the in-guest PT filter is enabled and deployed.
    ///
    /// This will happen if the #INTRO_OPT_IN_GUEST_PT_FILTER option was provided.
    /// Set by #IntPtiEnableFiltering and reset by #IntPtiDisableFiltering.
    BOOLEAN PtFilterEnabled;
    /// @brief  True if the in-guest PT filter was not yet injected, but it should be.
    ///
    /// This is used to properly re-inject the PT filter agent after a guest resumed from sleep. When the guest
    /// resumes, #IntPtiHandleGuestResumeFromSleep will set this to True if the #INTRO_OPT_IN_GUEST_PT_FILTER
    /// option is currently active. While this is True, calling #IntGuestPreReturnCallback with the
    /// #POST_RETRY_PERFAGENT option will inject the agent.
    BOOLEAN PtFilterWaiting;
    /// @brief  True if the \#VE agent was not yet injected, but it should be.
    ///
    /// This is used to properly re-inject the \#VE agent after a guest resumed from sleep. When the guest
    /// resumes, #IntVeHandleGuestResumeFromSleep will set this to True if the #INTRO_OPT_VE option is
    /// currently active. While this is True, calling #IntGuestPreReturnCallback with the
    /// #POST_RETRY_PERFAGENT option will inject the agent.
    BOOLEAN VeAgentWaiting;
    BOOLEAN VeInitialized; ///< Set to True if \#VE initialization was done.

    BOOLEAN SupportVE;     ///< Set to True if support for \#VE was detected.
    BOOLEAN SupportVMFUNC; ///< Set to True if support for VMFUNC was detected.
    BOOLEAN SupportSPP;    ///< Set to True if support for SPP was detected.
    BOOLEAN SupportDTR;    ///< Set to True if support for DTR access exits was detected.

    /// @brief  Set to True if the #INTRO_OPT_IN_GUEST_PT_FILTER was given, but it was removed.
    ///
    /// This can happen if both #INTRO_OPT_IN_GUEST_PT_FILTER, and #INTRO_OPT_VE are given and the \#VE
    /// mechanism was properly initialized, as we prefer to use \#VE instead of the PT filter when possible.
    /// If the loading of the \#VE agent fails and this is True, we will try to re-activate the PT filter.
    BOOLEAN PtFilterFlagRemoved;

    BYTE WordSize; ///< Guest word size. Will be 4 for 32-bit guests and 8 for 64-bit guests.

    /// @brief  Array of the VCPUs assigned to this guest. The index in this array matches the VCPU number.
    ///
    /// This is allocated in #IntGuestInit and freed in #IntGuestUninit.
    PVCPU_STATE VcpuArray;

    MM Mm; ///< Guest memory information, such as paging mode, system Cr3 value, etc

    /// @brief  The event ID on which introcore became active.
    ///
    /// Set in #IntWinGuestFinishInit for Windows guests and #IntLixGuestNew for Linux guests.
    /// This is used in order to disable any stats collecting done before relevant actions are done for
    /// introspecting a guest.
    QWORD IntroActiveEventId;

    DWORD RepOptsDisableCount; ///< The number of times the rep optimizations have been disabled.

    KERNEL_DRIVER *KernelDriver; ///< Points to the driver object that describes the kernel image.

    MSR_HOOK_STATE *MsrHooks; ///< MSR hook state.
    XCR_HOOK_STATE *XcrHooks; ///< XCR hook state.
    CR_HOOK_STATE *CrHooks;   ///< CR hook state.
    DTR_HOOK_STATE *DtrHooks; ///< DTR hook state.

    EXCEPTIONS *Exceptions; ///< The exceptions that are currently loaded.

    /// @brief  The EPTP index of the untrusted EPT.
    ///
    /// When \#VE is used, this is the EPT in which the guest is mapped.
    DWORD UntrustedEptIndex;
    /// @brief  The EPTP index of the trusted EPT.
    ///
    /// When \#VE is used, this is the EPT in which the \#VE agent is mapped.
    DWORD ProtectedEptIndex;

    void *GpaCache;         ///< The currently used GPA cache.
    void *InstructionCache; ///< The currently used instructions cache.

    SHEMU_CONTEXT Shemucontext; ///< Shellcode emulator context.
    
    /// @brief  The shellcode emulator shellcode buffer.
    BYTE ShemuShellcode[SHEMU_SHELLCODE_SIZE];
    /// @brief  The shellcode emulator stack buffer.
    BYTE ShemuStack[SHEMU_STACK_SIZE];
    /// @brief  The shellcode emulator internal buffer.
    BYTE ShemuInternal[SHEMU_SHELLCODE_SIZE + SHEMU_STACK_SIZE];

    /// @brief  Since the guest can be either Windows or Linux we can safely pack their specific
    /// states into an enum and use the appropriate field.
    union
    {
        LINUX_GUEST _LinuxGuest;     ///< Linux specific information. Valid when #OSType is #introGuestLinux.
        WINDOWS_GUEST _WindowsGuest; ///< Linux specific information. Valid when #OSType is #introGuestWindows.
    };
} GUEST_STATE, *PGUEST_STATE;


extern GUEST_STATE gGuest;
extern WINDOWS_GUEST *gWinGuest;
extern LINUX_GUEST *gLixGuest;

extern VCPU_STATE *gVcpu;

///
/// @brief  Flags that control the behavior of #IntGuestPreReturnCallback.
///
typedef enum
{
    POST_COMMIT_MEM = 0x00000001,       ///< Commit all the memory hooks.
    POST_COMMIT_MSR = 0x00000002,       ///< Commit all the MSR hooks.
    POST_COMMIT_CR = 0x00000004,        ///< Commit all the CR hooks.
    POST_COMMIT_XCR = 0x00000008,       ///< Commit all the XCR hooks.
    POST_COMMIT_DTR = 0x00000010,       ///< Commit all the DTR hooks.
    POST_INJECT_PF = 0x00000100,        ///< Inject pending page faults.
    POST_RETRY_PERFAGENT = 0x00000200,  ///< Reinject the \#VE or PT filtering agent, based on the active options.
} PRE_RET_OPTIONS;

//
// GUESTS related API
//
INTSTATUS
IntGuestGetInfo(
    _Out_ PGUEST_INFO GuestInfo
    );

INTSTATUS
IntGuestPreReturnCallback(
    _In_ DWORD Options
    );

void
IntGuestUpdateCoreOptions(
    _In_ QWORD NewOptions
    );

void
IntGuestUpdateShemuOptions(
     _In_ QWORD NewOptions
     );

INTSTATUS
IntGuestInit(
    _In_ QWORD Options
    );

void
IntGuestPrepareUninit(
    void
    );

void
IntGuestUninit(
    void
    );

INTSTATUS
IntGuestDisableIntro(
    _In_ QWORD Flags
    );

INTSTATUS
IntGuestGetLastGpa(
    _Out_ QWORD *MaxGpa
    );

void
IntGuestSetIntroErrorState(
    _In_ INTRO_ERROR_STATE State,
    _In_opt_ INTRO_ERROR_CONTEXT *Context
    );

INTRO_ERROR_STATE
IntGuestGetIntroErrorState(
    void
    );

INTRO_ERROR_CONTEXT *
IntGuestGetIntroErrorStateContext(
    void
    );

BOOLEAN
IntGuestShouldNotifyErrorState(
    void
    );


///
/// @brief      Checks if an address is inside one of the guest's IDTs
///
/// @param[in]  Address     The guest virtual address to be checked
/// @param[out] IdtBase     On success, the base of the IDT in which Address resides
/// @param[out] IdtLimit    On success, the limit of the IDT in which Address resides
///
/// @retval     #INT_STATUS_SUCCESS if Address is inside of one IDT
/// @retval     #INT_STATUS_NOT_FOUND is Address is not inside any IDT
///
__forceinline INTSTATUS
IntGuestGetIdtFromGla(
    _In_ QWORD Address,
    _Out_ QWORD *IdtBase,
    _Out_ QWORD *IdtLimit
    )
{
    for (DWORD cpuIndex = 0; cpuIndex < gGuest.CpuCount; cpuIndex++)
    {
        if (gGuest.VcpuArray[cpuIndex].IdtBase <= Address &&
            Address <= gGuest.VcpuArray[cpuIndex].IdtBase + gGuest.VcpuArray[cpuIndex].IdtLimit)
        {
            *IdtBase = gGuest.VcpuArray[cpuIndex].IdtBase;
            *IdtLimit = gGuest.VcpuArray[cpuIndex].IdtLimit;

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}

#endif // _GUESTS_H_
