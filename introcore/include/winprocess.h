/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winprocess.h
///
/// @brief  Exposes the types, constants and functions used to handle
/// Windows processes events (creation, termination, memory reads/writes, etc.).
///

#ifndef _WINPROCESS_H_
#define _WINPROCESS_H_

#include "winumpath.h"
#include "winguest.h"
#include "update_guests.h"
#include "windpi.h"
#include "winsecdesc.h"

struct _WIN_PROCESS_OBJECT;

#define WIN_STATUS_ACCESS_DENIED        0xC0000022      ///< Equivalent to NTSTATUS STATUS_ACCESS_DENIED
#define WIN_STATUS_SUCCESS              0x00000000      ///< Equivalent to NTSTATUS STATUS_SUCCESS


///
/// @brief  The Windows subsystem types.
///
typedef enum _WIN_SUBSYTEM_TYPE
{
    winSubsysUnknown = 0,       ///< Process subsystem type unknown.
    winSubsys64Bit,             ///< Process subsystem type 64 bit.
    winSubsys32Bit,             ///< Process subsystem type 32 bit.
} WIN_SUBSYTEM_TYPE;

///
/// @brief      Windows guest exit types.
///
typedef enum _WINPROC_GUEST_EXITS
{
    winProcExitVad          = 0x01,     ///< Exits caused by "MiCommitExistingVad".
    winProcExitWriteMemory  = 0x02,     ///< Exits caused by "MmCopyVirtualMemory".
    winProcExitReadMemory   = 0x04,     ///< Exits caused by "MmCopyVirtualMemory".
    winProcExitThreadCtx    = 0x08,     ///< Exits caused by "PspSetContextThreadInternal".
    winProcExitQueueApc     = 0x10,     ///< Exits caused by "NtQueueApcThreadEx".
    winProcExitSetProcInfo  = 0x20,     ///< Exits caused by "NtSetInformationProcess".
} WINPROC_GUEST_EXITS;


///
/// @brief      Windows process subsystem.
///
typedef struct _WIN_PROCESS_SUBSYSTEM
{
    struct _WIN_PROCESS_OBJECT  *Process;                   ///< The process object related to this subsystem.
    WIN_SUBSYTEM_TYPE           SubsystemType;              ///< Process subsystem type.

    QWORD                       PebAddress;                 ///< The Process Environment Block of this subsystem.

    DWORD                       ProtectedModulesCount;      ///< Number of protected modules inside this process.
    DWORD                       LoadedModulesCount;         ///< The number of modules that were loaded.

    /// @brief  The location of the system directory (where the system DLLs are located). For wow64 processes, it
    /// would be Windows\\SysWow64. For others, it would be Windows\\system32
    ///
    /// NOTE: Don't free, it's a reference
    const WCHAR                 *SystemDirPath;

    LIST_HEAD                   ProcessModules;             ///< List of process modules.

    BOOLEAN                     MainModuleLoaded;           ///< TRUE if the MainModule was loaded.
    BYTE                        NtdllLoadCount;             ///< Number of ntdll.dll loads.
    BYTE                        Kernel32LoadCount;          ///< Number of kernel32.dll loads.

    QWORD                       NtdllBase;                  ///< The base address for ntdll.dll.
    DWORD                       NtdllSize;                  ///< The size of ntdll.dll.
} WIN_PROCESS_SUBSYSTEM, *PWIN_PROCESS_SUBSYSTEM;

///
/// @brief  This structure describes a running process inside the guest.
///
typedef struct _WIN_PROCESS_OBJECT
{
    LIST_ENTRY          Link;                       ///< Entry within #gWinProcesses (Doubly Linked List).
    RBNODE              NodeCr3;                    ///< Entry within #gWinProcTreeCr3 (RB Tree).
    RBNODE              NodeUserCr3;                ///< Entry within #gWinProcTreeUserCr3 (RB Tree).
    RBNODE              NodeEproc;                  ///< Entry within #gWinProcTreeEprocess (RB Tree).

    QWORD               EprocessAddress;            ///< This will be the address of the ActiveProcess field.
    QWORD               ParentEprocess;             ///< The EPROCESS of the parent process.
    QWORD               RealParentEprocess;         ///< The active EPROCESS at the moment of creation.

    /// @brief  The creation time of the process, as stored inside the EPROCESS.
    QWORD               CreationTime;


    QWORD               Cr3;                        ///< Process PDBR. Includes PCID.
    QWORD               UserCr3;                    ///< Process user PDBR. Includes PCID.
    DWORD               Pid;                        ///< Process ID (the one used by Windows).
    DWORD               NameHash;                   ///< Name hash, as used by the exceptions module.

    QWORD               Peb64Address;               ///< PEB 64 address (on x86 OSes, this will be 0).
    QWORD               Peb32Address;               ///< PEB 32 address (on pure x64 processes, this will be 0).

    QWORD               MainModuleAddress;          ///< The address of the main module.

    CHAR                Name[IMAGE_BASE_NAME_LEN];  ///< Process base name.

    /// @brief  Will point inside the loaded modules list to the full process path.
    WINUM_PATH          *Path;

    /// @brief The command line with which the process was created (can be NULL).
    PCHAR               CommandLine;

    DWORD               CommandLineSize;            ///< Includes the NULL terminator

    union
    {
        /// @brief  Windows process flags (possible values for this bitmask are described below).
        DWORD           Flags;

        struct
        {
            DWORD           Wow64Process : 1;           ///< TRUE if this is a 32 bit process on a 64 bit OS.
            DWORD           Terminating : 1;            ///< TRUE if the process is terminating (cleanup pending).

            /// @brief TRUE if this is a protected process.
            /// If this is FALSE, most of the above fields aren't used at all.
            DWORD           Protected : 1;
            DWORD           IsAgent : 1;                ///< TRUE if this is an injected agent.
            DWORD           MainModuleLoaded : 1;       ///< TRUE if the main module has been loaded.
            DWORD           UnpackProtected : 1;        ///< TRUE if the main module has been protected against unpacks.
            DWORD           Initialized : 1;
            DWORD           BetaDetections : 1;         ///< TRUE if BETA is enabled for this particular process.
            DWORD           SystemProcess : 1;          ///< TRUE if this is a system process.
            DWORD           Lsass : 1;                  ///< TRUE if this is the lsass process.

            /// @brief  TRUE if the process was detected using a static scan (during static init).
            DWORD           StaticDetected : 1;

            /// @brief  TRUE if the write into PEB is done (used for initialization checks).
            DWORD           LastPebWriteDone : 1;
            DWORD           InjectedApphelp : 1;        ///< TRUE if AppHelp was injected.

            DWORD           ParentWow64 : 1;            ///< TRUE if the parent is a 32 bit process on a 64 bit OS.

            /// @brief  TRUE if the process actually started initializing (there is a time windows from the moment we
            /// add the inside out lists to the point when it actually starts its initialization steps
            /// when the process is "invalid").
            DWORD           StartInitializing : 1;

            DWORD           OneTimeInjectionDone : 1;   ///< The one time injection already took place (exception).
            DWORD           LateProtection : 1;         ///< TRUE if the protection was not activated right from start.

            /// @brief  TURE if the Process Environment Block (x86) context was written (valid only on Windows 7).
            DWORD           Peb32ContextWritten : 1;

            /// @brief  TURE if the Process Environment Block (x64) context was written (valid only on Windows 7).
            DWORD           Peb64ContextWritten : 1;

            DWORD           MonitorVad : 1;             ///< TRUE if we need to handle VAD events for this process.
            DWORD           MonitorModules : 1;         ///< TRUE if we need to monitor module load/unloads.
            DWORD           IsPreviousAgent : 1;        ///< TRUE if this is an agent injected in a previous session

            /// @brief TRUE if any Exploit Guard mitigation option is set for this process.
            DWORD           ExploitGuardEnabled : 1;

            DWORD           Outswapped : 1;             ///< TRUE if the process is outswapped.
        };
    };

    BYTE                InjectionsCount;            ///< The number of injections allowed at the initialization.
    BYTE                PebWrittenCount;            ///< The number writes to the (Process Environment Block).

    QWORD               InjectedApphelpAddress;     ///< The address of the injected apphelp (during initialization).
    DWORD               InjectedAppHelpSize;        ///< The size of the injected apphelp (during initialization).

    DWORD               LastException;              ///< The code of the last exception that took place.
    QWORD               LastExceptionRip;           ///< The RIP of the last exception that took place.

    /// @brief  TRUE if the last exception is continuable (for example a \#PF that was caused due to the way
    /// the OS does the lazy memory mappings).
    BOOLEAN             LastExceptionContinuable;

    /// @brief  Only valid for chromium-based browsers; TRUE if this is a NaCl process.
    BOOLEAN             HasNaClEnabled;

    BOOLEAN             EnforcedDep;                ///< TRUE is the DEP (Data Execution Prevention) has been enforced.

    /// @brief The exit status of the process (used when sending the process terminated event).
    DWORD               ExitStatus;

    BOOLEAN             IsDominoJava;               ///< True if this is a Java IBM process and j9jit.dll is loaded.
    BOOLEAN             FirstDominoJavaIgnored;     ///< TRUE if the first Domino Java execution VAD was ignored.

    union
    {
        /// @brief  Protection mask: tells us what level of protection will be activated for this process.
        DWORD           ProtectionMask;

        struct
        {
            DWORD       ProtReserved1 : 2;          ///< RESERVED.
            DWORD       ProtCoreModules : 1;        ///< Protect the core module loaded by the process.
            DWORD       ProtUnpack : 1;             ///< Protect process against unpacking attempts.
            DWORD       ProtWriteMem : 1;           ///< Protect the the memory against writes.
            DWORD       ProtWsockModules : 1;       ///< Protect the Windows Socket related modules.
            DWORD       ProtExploits : 1;           ///< Protect the process against exploits.
            /// @brief  Protect the thread context (protection against thread hijacking).
            DWORD       ProtThreadCtx : 1;

            DWORD       ProtQueueApc : 1;           ///< Protect APC Queue of the process (APC hijacking).
            /// @brief Prevent this process from creating child processes (other than  other instances of itself).
            DWORD       ProtCreation: 1;

            DWORD       ProtDoubleAgent : 1;        ///< Protect the process against double agent attacks.
            DWORD       ProtScanCmdLine : 1;        ///< Scan the cmd line of the process.
            DWORD       ProtInstrument : 1;         ///< Protect the process agains instrumentation callback attacks.
            DWORD       ProtReserved2 : 16;         ///< RESERVED.
            /// @brief  Any event inside the process will trigger the injection of  the remediation tool.
            DWORD       ProtRemediate : 1;

            DWORD       ProtKillExploit : 1;        ///< The process will be killed if an exploit is detected.
            /// @brief  Process is monitored, but in log-only mode so no actions will be blocked.
            DWORD       ProtBeta : 1;
        };
    };

    QWORD               BetaMask;                   ///< The protection mask in beta mode.
    QWORD               FeedbackMask;               ///< The protection mask in feedback mode.

    DWORD               AgentTag;                   ///< If IsAgent is TRUE, this will be the agent tag.

    /// @brief  The CR3 will be locked in memory, to prevent the OS from dynamically modifying
    /// the CR3 of a running process.
    void                *Cr3PageLockObject;

    /// @brief The UserCR3 will be locked in memory, to prevent the OS from dynamically
    /// modifying the CR3 of a running process.
    void                *UserCr3PageLockObject;

    RBTREE              VadTree;                    ///< RB-Tree of process VADs.
    void                *VasMonRoot;                ///< Virtual Address Space monitor root.
    LIST_HEAD           *VadPages;                  ///< Vad pages Hash-Table.

    QWORD               OriginalTokenPtr;           ///< Original Token pointer inside EPROCESS (should never change).

    /// @brief  The swap memory handle for Process->Peb->ProcessParameters
    /// (used to read the command line of the process).
    void                *ParamsSwapHandle;

    /// @brief  The swap memory handle for the UNICODE_STRING containing the
    /// command line of the a process.
    void                *CmdLineSwapHandle;

    void                *CmdBufSwapHandle;          ///< The swap memory handle for the command line buffer.

    void                *SelfMapHook;               ///< The self mapping memory hook.
    void                *UserSelfMapHook;           ///< The user self mapping memory hook.

    QWORD               SelfMapEntryValue;          ///< The self mapping memory entry value.
    QWORD               UserSelfMapEntryValue;      ///< The user  self mapping memory entry value.

    /// @brief  Context from integrator if the process is protected,  0 otherwise.
    QWORD               Context;

    BOOLEAN             ImageIsFromNativeSubsystem;  ///< TRUE if the process image is from the native subsystem.
    BOOLEAN             IsVerifierLoaded;            ///< TRUE if app verifier is loaded.

    /// @brief  We put in guest * and some flags in order to decide whether to raise a VM  exit on a process.
    /// Here we keep the overwritten original value of the spare field.
    WORD                OriginalSpareValue;

    /// @brief  Used for keeping the main module VAD (used for dereferencing paths) as
    /// the unprotected processes don't have a VAD RB-Tree.
    void                *MainModuleVad;

    struct
    {
        BOOLEAN             ParentHasPivotedStack;      ///< The parent process has a pivoted stack.

        /// @brief  This will keep the EPROCESS of the debugger process (if any).
        QWORD               DebuggerEprocess;

        /// @brief This will keep the EPROCESS of the process from which the current process stole the token.
        QWORD               TokenStolenFromEprocess;

        BOOLEAN             ParentHasBeenHeapSprayed;   ///< The parent process has been heap sprayed.

        /// @brief The parent process has the token privileges altered in a malicious way, most probably due to a
        /// privilege escalation.
        BOOLEAN             ParentHasTokenPrivsAltered;

        BOOLEAN             ParentThreadSuspicious;     ///< The parent thread start address was considered suspicious.

        /// @brief The parent process has an altered security descriptor pointer.
        BOOLEAN             ParentHasAlteredSecDescPtr;

        /// @brief The parent process has an altered ACL (SACL/DACL).
        BOOLEAN             ParentHasEditedAcl;
    } CreationInfo;

    DPI_EXTRA_INFO          DpiExtraInfo;   ///< Represents the gathered extra info while checking the DPI heuristics.

    /// @brief  The x86 subsystem. Note that a 32 bit process on a 64 bit OS may have both subsystems valid.
    /// In that case,  we need to handle & protect both of them.
    PWIN_PROCESS_SUBSYSTEM Subsystemx86;

    /// @brief  The x64 subsystem. Note that a 32 bit process on a 64 bit OS may have both subsystems valid.
    /// In that case,  we need to handle & protect  both of them.
    PWIN_PROCESS_SUBSYSTEM Subsystemx64;

    void                    *TokenHook;      ///< Hook object for the ept hook over nt!_TOKEN Privileges field.

    /// @brief  Hook object for notifications over the swap-in/swap-out of the current process TOKEN.
    /// We need to place this hook in order to verify on translation modifications of the current TOKEN if it
    /// is still assigned to the current process. The token might get deallocated in the mean-time and the page
    /// can be used, for example, for mapping other physical pages, thus leading to translation violations when
    /// the hashes of the contents are checked. For this purpose we will verify on every translation modification event
    /// if the current token is still used, and re-establish the hook over the token if it was previously de-allocated.
    void                   *TokenSwapHook;

    /// @brief  Saved value of the Privileges Present bitfield inside the nt!_TOKEN structure assigned to the current
    /// process.
    QWORD                   OriginalPresentPrivs;

    /// @brief  Saved value of the Privileges Enabled bitfield inside the nt!_TOKEN structure assigned to the current
    /// process.
    QWORD                   OriginalEnabledPrivs;

    /// @brief  Signals whether the next privileges check on integrity should be skipped for the current process.
    /// Is set if, for example, we could not fetch the privileges when the process was created.
    BOOLEAN                 SkipPrivsNextCheck;

    /// @brief  Set to TRUE when a token privilege change has been detected.
    /// This is useful for DPI, in the case where a write has been detected over the privileges, but because of the
    /// detect only mechanism, we have overwritten the OriginalPresentPrivs and OriginalEnabledPrivs values, thus
    /// DPI will not raise an alert on process creation due to the fact that the mechanism doesn't see any change.
    /// For this purpose, we'll analyze every process creation in DPI from the moment the privileges have changed
    /// and a detection took place on integrity.
    BOOLEAN                 PrivsChangeDetected;

    /// @brief  Set to TRUE when the difference between Enabled and Present privileges is just one bit.
    /// As on some OS versions, when a privilege is removed for a token belonging to a process, firstly the kernel
    /// removes the Present bit, and on the next instruction it removes the Enabled bit, it will cause a possible
    /// race condition. If the timer exit comes just between those instructions, we will wrongfully give a detection.
    /// For this purpose, we'll set this variable if there is just one bit difference, and we expect on the next
    /// timer check that the difference is not present anymore. However, if there's one bit difference again on the
    /// next exit, then it is likely due to a malicious behavior.
    BOOLEAN                 PrivsChangeOneBit;

    struct  
    {
        /// @brief  Security descriptor address.
        QWORD                   SecurityDescriptorGva;

        /// @brief  The entire security descriptor contents.
        BYTE                    RawBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];

        /// @brief  The used actual size of the RawBuffer.
        DWORD                   RawBufferSize;

        /// @brief  The System Access Control List header.
        ACL                     Sacl;

        /// @brief  The Discretionary Access Control List header.
        ACL                     Dacl;
    } SecurityDescriptor;

} WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;


static __forceinline QWORD
IntWinProcGetProtOption(
    _In_ const WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Get the protection type for the given process.
///
/// @param[in]  Process     The process object.
///
/// @retval     #INTRO_OPT_PROT_UM_SYS_PROCS     If the given process is system process.
/// @retval     #INTRO_OPT_PROT_UM_MISC_PROCS    If the given process is NOT system process.
///
{
    return Process->SystemProcess ? INTRO_OPT_PROT_UM_SYS_PROCS : INTRO_OPT_PROT_UM_MISC_PROCS;
}

static __forceinline BOOLEAN
IntWinProcPolicyIsBeta(
    _In_ const WIN_PROCESS_OBJECT *Process,
    _In_ QWORD Flag
    )
///
/// @brief      Checks if the given process is protected with the provided flag (in beta mode).
///
/// @param[in]  Process     The process object.
/// @param[in]  Flag        The protection flag to be checked.
///
/// @retval     TRUE    If the process is protected with the provided flag (in beta mode).
/// @retval     FALSE   If the process is NOT protected with the provided flag (in beta mode).
///
{
    return Process->BetaDetections ||
           IntPolicyCoreIsOptionBeta(IntWinProcGetProtOption(Process)) ||
           (Process->BetaMask & Flag) != 0;
}

static __forceinline BOOLEAN
IntWinProcPolicyIsFeedback(
    _In_ const WIN_PROCESS_OBJECT *Process,
    _In_ QWORD Flag
    )
///
/// @brief      Checks if the given process is protected with the provided flag (in feedback mode).
///
/// @param[in]  Process     The process object.
/// @param[in]  Flag        The protection flag to be checked.
///
/// @retval     TRUE    If the process is protected with the provided flag (in feedback mode).
/// @retval     FALSE   If the process is NOT protected with the provided flag (in feedback mode).
///
{
    return ((Process->FeedbackMask & Flag) ||
            (IntPolicyIsCoreOptionFeedback(IntWinProcGetProtOption(Process))));
}

INTSTATUS
IntWinProcHandleCreate(
    _In_ void *Detour
    );

INTSTATUS
IntWinProcHandleTerminate(
    _In_ void *Detour
    );

INTSTATUS
IntWinProcHandleCopyMemory(
    _In_ void *Detour
    );

INTSTATUS
IntWinProcSwapIn(
    _In_  void *Detour
    );

INTSTATUS
IntWinProcSwapOut(
    _In_  void *Detour
    );

INTSTATUS
IntWinProcPatchCopyMemoryDetour(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinProcPatchPspInsertProcess86(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinProcPatchSwapOut64(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinProcPatchSwapOut32(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinProcProtect(
    _In_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinProcUnprotect(
    _In_ WIN_PROCESS_OBJECT *Process
    );

const PROTECTED_PROCESS_INFO *
IntWinProcGetProtectedInfoEx(
    _In_ PWCHAR Path,
    _In_ BOOLEAN IsSystem
    );

INTSTATUS
IntWinProcUpdateProtection(
    void
    );

INTSTATUS
IntWinProcCreateProcessObject(
    _Out_ WIN_PROCESS_OBJECT **Process,
    _In_ QWORD EprocessAddress,
    _In_ PBYTE EprocessBuffer,
    _In_ QWORD ParentEprocess,
    _In_ QWORD RealParentEprocess,
    _In_ QWORD Cr3,
    _In_ DWORD Pid,
    _In_ BOOLEAN StaticScan
    );

INTSTATUS
IntWinProcValidateSystemCr3(
    void
    );

INTSTATUS
IntWinProcAddProtectedProcess(
    _In_ const WCHAR *Path,
    _In_ DWORD ProtectionMask,
    _In_ QWORD Context
    );

INTSTATUS
IntWinProcRemoveProtectedProcess(
    _In_ const WCHAR *Path
    );

INTSTATUS
IntWinProcRemoveAllProtectedProcesses(
    void
    );

void
IntWinProcDumpProtected(
    void
    );

void
IntWinProcUninit(
    void
    );

INTSTATUS
IntWinProcGetObjectByPid(
    _In_ DWORD Pid,
    _Outptr_ WIN_PROCESS_OBJECT **Process
    );

INTSTATUS
IntWinProcReadCommandLine(
    _In_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinProcChangeProtectionFlags(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ DWORD OldMask,
    _In_ DWORD NewMask
    );

void
IntWinProcUpdateProtectedProcess(
    _In_ const void *Name,
    _In_ const CAMI_STRING_ENCODING Encoding,
    _In_ const CAMI_PROT_OPTIONS *Options
    );

INTSTATUS
IntWinProcHandleInstrument(
    _In_ void *Detour
    );

INTSTATUS
IntWinProcPrepareInstrument(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

#endif // _WINPROCESS_H_
