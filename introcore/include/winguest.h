/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINGUEST_H_
#define _WINGUEST_H_

#include "introcore.h"
#include "patsig.h"
#include "detours.h"

typedef struct _GUEST_STATE GUEST_STATE, *PGUEST_STATE;

/// @brief  The maximum length of a process name
#define IMAGE_BASE_NAME_LEN 16u

/// @brief  The maximum length of a process path
#define IMAGE_FULL_PATH_LEN 260u

/// @brief  Flag used to represent internally that a process is protected by name, not by path
#define PROT_PROC_FLAG_NO_PATH 0x00000001

/// @brief  Encapsulates a protected Windows process
typedef struct _PROTECTED_PROCESS_INFO
{
    /// @brief  Process name pattern
    ///
    /// This is used as a glob pattern in order to match a process name
    CHAR        ImageBaseNamePattern[IMAGE_BASE_NAME_LEN];

    /// @brief  The protection flags used for this process
    ///
    /// All the fields are a combination of @ref group_process_options values
    struct
    {
        /// @brief  The original protection flags as received from #GLUE_IFACE.AddRemoveProtectedProcessUtf16 or
        /// #GLUE_IFACE.AddRemoveProtectedProcessUtf8
        DWORD   Original;
        /// @brief  The currently used protection flags
        ///
        /// These are the #Original flags, but the #CAMI_PROT_OPTIONS settings may change them by forcing some flags
        /// to be off or on, overriding the protection policy. This allows us to disable problematic options just by
        /// updating the market CAMI file.
        DWORD   Current;

        /// @brief  Flags that were forced to beta (log-only) mode
        ///
        /// This can be done by the CAMI mechanism. These are the CAMI_PROT_OPTIONS.ForceBeta flags. Detections
        /// triggered by the protection mechanism enabled by these flags will never block, the action taken will
        /// always be #introGuestAllowed, and an alert will be generated.
        QWORD   Beta;
        /// @brief  Flags that will be forced to feedback only mode
        ///
        /// This can be done by the CAMI mechanism. These are the CAMI_PROT_OPTIONS.ForceFeedback flags. Detections
        /// triggered by the protection mechanism enabled by these flags will never block, the action taken will
        /// always be #introGuestAllowed, an alert will be generated, but it will have the #ALERT_FLAG_FEEDBACK_ONLY;
        /// the user will not be notified, the event will generate feedback.
        QWORD   Feedback;
    } Protection;

    /// @brief  Flags that describe the protection mode
    ///
    /// Can be either 0 or #PROT_PROC_FLAG_NO_PATH
    DWORD       Flags;
    /// @brief  Full application path pattern
    PWCHAR      FullPathPattern;
    /// @brief  Full application name pattern
    ///
    /// This points inside #FullPathPattern
    PWCHAR      FullNamePattern;
    /// @brief  The context supplied in the protection policy
    ///
    /// This is the Context parameter of the #GLUE_IFACE.AddRemoveProtectedProcessUtf16 and
    /// #GLUE_IFACE.AddRemoveProtectedProcessUtf8 APIs
    QWORD       Context;

    /// @brief  Entry inside the #gWinProtectedProcesses list
    LIST_ENTRY  Link;
} PROTECTED_PROCESS_INFO, *PPROTECTED_PROCESS_INFO;

///
/// @brief  Describes a pattern for a kernel function that is not exported
///
/// Functions that are not exported can not be found by name, so we search them by a pattern
typedef struct _WIN_UNEXPORTED_FUNCTION_PATTERN
{
    /// @brief  Optional section name hint
    ///
    /// If not empty, will search in the given section
    CHAR                SectionHint[8];
    /// @brief  The pattern signature
    PATTERN_SIGNATURE   Signature;
    DETOUR_ARGS         Arguments;
} WIN_UNEXPORTED_FUNCTION_PATTERN, *PWIN_UNEXPORTED_FUNCTION_PATTERN;


///
/// @brief  Describes a function that is not exported
///
/// This structure has a variable length
typedef struct _WIN_UNEXPORTED_FUNCTION
{
    /// @brief  Crc32 checksum of the function name
    DWORD                           NameHash;

    /// @brief  The number of entries in the Patterns array
    DWORD                           PatternsCount;
    _Field_size_(PatternsCount)
    WIN_UNEXPORTED_FUNCTION_PATTERN Patterns[0]; ///< The patterns used to search for this function
} WIN_UNEXPORTED_FUNCTION, *PWIN_UNEXPORTED_FUNCTION;

///
/// @brief  Protected kernel module types
///
typedef enum
{
    winModNone = 0,  ///< Invalid
    winModCore,      ///< Core Windows kernel modules
    winModAntivirus, ///< Antivirus modules
    winModCitrix,    ///< Xen-specific Citrix modules
} PROTECTED_MODULE_TYPE;

///
/// @brief  Encapsulates a protected Windows kernel module
///
typedef struct _PROTECTED_MODULE_INFO
{
    PROTECTED_MODULE_TYPE   Type;   ///< The type of the module
    const WCHAR             *Name;  ///< The name of the module
    const WCHAR             *Path;  ///< The path from which the module is loaded
    /// @brief  The driver object that must be protected when protecting this module
    ///
    /// It may be NULL, in which case no driver object will be protected.
    const WCHAR             *DriverObject;

    /// @brief  The introcore options that need to be active in order to protect this module
    ///
    /// These are a combination of @ref group_options values
    QWORD                   RequiredFlags;
} PROTECTED_MODULE_INFO, *PPROTECTED_MODULE_INFO;

///
/// @brief  Describes the mode in which a kernel object was found.
///
typedef enum
{
    /// @brief  The object was detected after it was created.
    ///
    /// This usually implies a memory scan of some type.
    FLAG_STATIC_DETECTION = 1,
    /// @brief  The object was detected when it was created.
    FLAG_DYNAMIC_DETECTION = 2,
} OBJ_DISCOVERY_TYPE;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Um.Dll array, containing offsets inside the
/// _LDR_DATA_TABLE_ENTRY structure.
///
/// @ingroup    group_guest_support
///
/// The #WIN_UM_FIELD macro can be used to access these more easily.
typedef enum _WIN_UM_FIELD_DLL
{
    winUmFieldDllBaseOffsetInModule64 = 0,  ///< The offset of the DllBase field for 64-bit modules.
    winUmFieldDllBaseOffsetInModule32,      ///< The offset of the DllBase field for 32-bit modules.
    winUmFieldDllSizeOffsetInModule64,      ///< The offset of the SizeOfImage field for 64-bit modules.
    winUmFieldDllSizeOffsetInModule32,      ///< The offset of the SizeOfImage field for 64-bit modules.
    winUmFieldDllNameOffsetInModule64,      ///< The offset of the FullDllName field for 64-bit modules.
    winUmFieldDllNameOffsetInModule32,      ///< The offset of the FullDllName field for 32-bit modules.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winUmFieldDllEnd
} WIN_UM_FIELD_DLL;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Um.Peb array, containing offsets inside the _PEB structure.
/// @ingroup    group_guest_support
///
/// These are the indexes of the offsets inside the WIN_OPAQUE_FIELDS.Um.Peb array. The #WIN_UM_FIELD can be used
/// to access these more easily.
typedef enum _WIN_UM_FIELD_PEB
{
    winUmFieldPeb64Size = 0,    ///< The relevant size of the _PEB for 64-bit processes.
    winUmFieldPeb32Size,        ///< The relevant size of the _PEB for 32-bit processes.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winUmFieldPebEnd
} WIN_UM_FIELD_PEB;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Um.Teb array, containing offsets inside the _TEB structure.
/// @ingroup    group_guest_support
///
/// The #WIN_UM_FIELD macro can be used to access these more easily
typedef enum _WIN_UM_FIELD_TEB
{
    winUmFieldTeb64Size = 0,            ///< The relevant size of the _TEB for 64-bit processes
    winUmFieldTeb32Size,                ///< The relevant size of the _TEB for 32-bit processes
    /// The offset of the area in which a thread of a WoW64 application saves its general purpose registers when
    /// jumping to 64-bit code in order to issue a syscall
    winUmFieldTebWow64SaveArea,
    /// The offset of the ESP in the #winUmFieldTebWow64SaveArea
    winUmFieldTebWow64StackInSaveArea,
    /// @brief  The end of the fields
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries
    winUmFieldTebEnd
} WIN_UM_FIELD_TEB;

///
/// @brief  Structure tags used for the kernel mode structures.
/// @ingroup    group_guest_support
///
/// Each of these refers to a #WIN_OPAQUE_FIELDS.Km field.
typedef enum _WIN_KM_STRUCTURE
{
    winKmStructureProcess = 0,    ///< Used for the WIN_OPAQUE_FIELDS.Km.Process array.
    winKmStructureThread,         ///< Used for the WIN_OPAQUE_FIELDS.Km.Thread array.
    winKmStructureDrvObj,         ///< Used for the WIN_OPAQUE_FIELDS.Km.DrvObj array.
    winKmStructurePcr,            ///< Used for the WIN_OPAQUE_FIELDS.Km.Pcr array.
    winKmStructurePoolDescriptor, ///< Used for the WIN_OPAQUE_FIELDS.Km.PoolDescriptor array.
    winKmStructureMmpfn,          ///< Used for the WIN_OPAQUE_FIELDS.Km.Mmpfn array.
    winKmStructureToken,          ///< Used for the WIN_OPAQUE_FIELDS.Km.Token array.
    winKmStructureUngrouped,      ///< Used for the WIN_OPAQUE_FIELDS.Km.Ungrouped array.
    winKmStructureEprocessFlags,  ///< Used for the WIN_OPAQUE_FIELDS.Km.EprocessFlags array.
    winKmStructureVadShort,       ///< Used for the WIN_OPAQUE_FIELDS.Km.VadShort array.
    winKmStructureVadLong,        ///< Used for the WIN_OPAQUE_FIELDS.Km.VadLong array.
    winKmStructureVadFlags,       ///< Used for the WIN_OPAQUE_FIELDS.Km.VadFlags array.
    winKmStructureSyscallNumbers, ///< Used for the WIN_OPAQUE_FIELDS.Km.SyscallNumbers array.
    winKmStructureFileObject,     ///< Used for the WIN_OPAQUE_FIELDS.Km.FileObject array.
    /// @brief  The end of the tags.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmStructureEnd
} WIN_KM_STRUCTURE;

///
/// @brief  Structure tags used for the user mode structures.
/// @ingroup    group_guest_support
///
/// Each of these refers to a #WIN_OPAQUE_FIELDS.Um field.
typedef enum _WIN_UM_STRUCTURE
{
    winUmStructureDll = 0,  ///< Used for the WIN_OPAQUE_FIELDS.Um.Dll array.
    winUmStructurePeb,      ///< Used for the WIN_OPAQUE_FIELDS.Um.Peb array.
    winUmStructureTeb,      ///< Used for the WIN_OPAQUE_FIELDS.Um.Teb array.
    /// @brief  The end of the tags.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winUmStructureEnd
} WIN_UM_STRUCTURE;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Process array, containing offsets inside the _EPROCESS structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_PROCESS
{
    winKmFieldProcessCr3 = 0,          ///< Offset of Pcb.DirectoryTableBase.
    /// @brief  Offset of Pcb.UserDirectoryTableBase if it exists, DirectoryTableBase if not.
    winKmFieldProcessUserCr3,
    winKmFieldProcessKexecOptions,     ///< Offset of Pcb.Flags.
    winKmFieldProcessListEntry,        ///< Offset of ActiveProcessLinks.
    winKmFieldProcessName,             ///< Offset of ImageFileName.
    winKmFieldProcessSectionBase,      ///< Offset of SectionBaseAddress.
    winKmFieldProcessId,               ///< Offset of UniqueProcessId.
    winKmFieldProcessParentPid,        ///< Offset of InheritedFromUniqueProcessId.
    winKmFieldProcessVadRoot,          ///< Offset of VadRoot.
    winKmFieldProcessCreateTime,       ///< Offset of CreateTime.
    winKmFieldProcessExitStatus,       ///< Offset of ExitStatus.
    winKmFieldProcessToken,            ///< Offset of Token.
    winKmFieldProcessObjectTable,      ///< Offset of ObjectTable.
    winKmFieldProcessPeb,              ///< Offset of Peb.
    winKmFieldProcessThreadListHead,   ///< Offset of Pcb.ThreadListHead.
    winKmFieldProcessWoW64,            ///< Offset of Wow64Process (only for 64-bit guests).
    winKmFieldProcessFlags,            ///< Offset of Flags.
    winKmFieldProcessFlags3,           ///< Offset of Flags3.
    winKmFieldProcessMitigationFlags,  ///< Offset of MitigationFlags if it exists (>= RS3).
    winKmFieldProcessMitigationFlags2, ///< Offset of MitigationFlags2 if it exists (>= RS3).
    winKmFieldProcessDebugPort,        ///< Offset of DebugPort (needed for DPI Debug Flag).
    /// @brief  The offset at which spare space is found inside the structure.
    ///
    /// It is safe for introcore to change these fields (for example, for inserting protection data).
    winKmFieldProcessSpare,

    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldProcessEnd
} WIN_KM_FIELD_PROCESS;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Thread array, containing offsets inside the _ETHREAD structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_THREAD
{
    winKmFieldThreadProcess = 0,        ///< Offset of Tcb.Process.
    winKmFieldThreadThreadListEntry,    ///< Offset of Tcb.ThreadListEntry (not the one found directly in the _ETHREAD).
    winKmFieldThreadKernelStack,        ///< Offset of Tcb.KernelStack.
    winKmFieldThreadStackBase,          ///< Offset of Tcb.StackBase.
    winKmFieldThreadStackLimit,         ///< Offset of Tcb.StackLimit.
    winKmFieldThreadState,              ///< Offset of Tcb.State.
    winKmFieldThreadWaitReason,         ///< Offset of Tcb.WaitReason.
    winKmFieldThreadAttachedProcess,    ///< Offset of Tcb.ApcState.Process.
    winKmFieldThreadTeb,                ///< Offset of Tcb.Teb.
    winKmFieldThreadId,                 ///< Offset of Cid.UniqueThread.
    winKmFieldThreadClientSecurity,     ///< Offset of ClientSecurity.
    winKmFieldThreadTrapFrame,          ///< Offset of Tcb.TrapFrame.
    winKmFieldThreadWin32StartAddress,  ///< Offset of Win32StartAddress.
    winKmFieldThreadPreviousMode,       ///< Offset of PreviousMode.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldThreadEnd
} WIN_KM_FIELD_THREAD;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.DrvObj array, containing information about the _DRIVER_OBJECT structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_DRVOBJ
{
    /// @brief  The size of the _DRIVER_OBJECT structure.
    ///
    /// This is the size protected by introcore when protecting driver objects due to the #INTRO_OPT_PROT_KM_DRVOBJ
    /// protection flag.
    winKmFieldDrvObjSize = 0,
    /// @brief  The size of the _FAST_IO_DISPATCH structure.
    ///
    /// This is the size protected by introcore when protecting driver objects due to the #INTRO_OPT_PROT_KM_DRVOBJ
    /// protection flag.
    winKmFieldDrvObjFiodispSize,
    /// @brief  The size of the allocation that precedes a driver object, excluding the POOL_HEADER (0x8/0x10 bytes).
    winKmFieldDrvObjAllocationGap,
    winKmFieldDrvObjFiodisp,       ///< Offset of FastIoDispatch.
    winKmFieldDrvObjStart,         ///< Offset of DriverStart.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldDrvObjEnd
} WIN_KM_FIELD_DRVOBJ;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Pcr array, containing information about the _KPCR structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_PCR
{
    winKmFieldPcrCurrentThread = 0,         ///< Offset of PrcbData.CurrentThread.
    winKmFieldPcrUserTime,                  ///< Offset of PrcbData.UserTime.
    winKmFieldPcrPcrb,                      ///< Offset of Prcb inside KPCR.
    winKmFieldPcrPrcbInterruptObject,       ///< Offset of InterruptObject inside KPRCB.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldPcrEnd
} WIN_KM_FIELD_PCR;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.PoolDescriptor array, containing information about the
/// _POOL_DESCRIPTOR structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_POOLDESCRIPTOR
{
    winKmFieldPoolDescriptorTotalBytes = 0, ///< Offset of TotalBytes.
    winKmFieldPoolDescriptorNppSize,        ///< The size of the non paged pool.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldPoolDescriptorEnd
} WIN_KM_FIELD_POOLDESCRIPTOR;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Mmpfn array, containing information about the _MMPFN structure.
/// @ingroup    group_guest_support
///
/// For 32-bit versions of the OS, this is split into two sections: PAE and non-PAE, as Windows versions prior to
/// Windows 8 were able to boot without PAE support and in those cases the _MMPFN structure was different.
/// For 32-bit guests with PAE enabled (#gGuest->Mm.Mode is #PAGING_PAE_MODE in those cases) the Pae version of the
/// tags should be used. For the other guests, the normal versions should be used.
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_MMPFN
{
    winKmFieldMmpfnSize = 0,    ///< The size of the _MMPFN structure.
    winKmFieldMmpfnPte,         ///< Offset of PteAddress (or PteLong).
    winKmFieldMmpfnRefCount,    ///< Offset of u3.ReferenceCount.
    winKmFieldMmpfnFlags,       ///< Offset of u3.e1.

    winKmFieldMmpfnPaeSize,     ///< The size of the _MMPFN structure when PAE is enabled.
    winKmFieldMmpfnPaePte,      ///< Offset of PteAddress (or PteLong) when PAE is enabled.
    winKmFieldMmpfnPaeRefCount, ///< Offset of u3.ReferenceCount when PAE is enabled.
    winKmFieldMmpfnPaeFlags,    ///< Offset of u3.e1 when PAE is enabled.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldMmpfnEnd
} WIN_KM_FIELD_MMPFN;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Token array, containing information about the _TOKEN structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_TOKEN
{
    winKmFieldTokenPrivs = 0,       ///< Offset of Privileges.
    winKmFieldTokenUserCount,       ///< Offset of UserAndGroupCount.
    winKmFieldTokenRestrictedCount, ///< Offset of RestrictedSidCount.
    winKmFieldTokenUsers,           ///< Offset of UserAndGroups.
    winKmFieldTokenRestrictedSids,  ///< Offset of RestrictedSids.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldTokenEnd
} WIN_KM_FIELD_TOKEN;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.Ungrouped array, containing information about various kernel structures
/// or data.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_UNGROUPED
{
    winKmFieldUngroupedCtlAreaFile = 0,         ///< Offset of FilePointer in _CONTROL_AREA.
    winKmFieldUngroupedHandleTableTableCode,    ///< Offset of TableCode _HANDLE_TABLE.
    winKmFieldUngroupedHalIntCtrlType,          ///< Offset of InterruptControllerType.
    winKmFieldUngroupedWmiGetClockOffset,       ///< Offset of GetCpuClock in _WMI_LOGGER_CONTEXT.
    winKmFieldUngroupedEtwDbgDataSiloOffset,    ///< Offset of EtwDbgDataSilo in EtwpDbgData.
    /// @brief The offset relative tot he EtwDebuggerData structure at which the ETW signature is found.
    winKmFieldUngroupedEtwSignatureOffset,
    winKmFieldUngroupedSubsectionCtlArea,       ///< Offset of ControlArea in _SUBSECTION.
    winKmFieldUngroupedHalPerfCntFunctionOffset,///< Offset of protected function in HalPerformanceCounter.
    /// @brief The offset of the restored RSP value taken from RBP, which serves as a fake trapframe on
    /// Zw* calls on x64. This will be equal to 0 on x86 and should not be used on this architecture.
    winKmFieldUngroupedRspOffsetOnZwCall,
    winKmFieldUngroupedHalIntCtrlTypeMaxOffset, ///< The maximum offset of Type inside HalInterruptController.
    winKmFieldUngroupedHalIntCtrlTypeMinOffset, ///< The minimum offset of Type inside HalInterruptController.
    winKmFieldUngroupedSharedUserDataSize,      ///< The size of the _KUSER_SHARED_DATA structure.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldUngroupedEnd
} WIN_KM_FIELD_UNGROUPED;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.EprocessFlags array, containing information about the flags inside
/// the _EPROCESS structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_EPROCESSFLAGS
{
    winKmFieldEprocessFlagsNoDebugInherit = 0, ///< Mask for NoDebugInherit from _EPROCESS.Flags.
    winKmFieldEprocessFlagsExiting,            ///< Mask for Exiting from _EPROCESS.Flags.
    winKmFieldEprocessFlagsDelete,             ///< Mask for Delete from _EPROCESS.Flags.
    winKmFieldEprocessFlags3Crashed,           ///< Mask for Flag3Crashed from _EPROCESS.Flags.
    winKmFieldEprocessFlagsVmDeleted,          ///< Mask for VmDeleted from _EPROCESS.Flags.
    winKmFieldEprocessFlagsHasAddrSpace,       ///< Mask for HasAddrSpace from _EPROCESS.Flags.
    winKmFieldEprocessFlagsOutSwapped,         ///< Mask for OutSwapped from _EPROCESS.Flags.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldEprocessFlagsEnd
} WIN_KM_FIELD_EPROCESSFLAGS;

///
/// @brief   Indexes in the WIN_OPAQUE_FIELDS.Km.VadShort array, containing information about the _MMVAD_SHORT
/// structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_VAD_SHORT
{
    /// Offset of ParentValue.
    winKmFieldVadShortParent = 0,
    /// Offset of LeftChild.
    winKmFieldVadShortLeft,
    /// Offset of RightChild.
    winKmFieldVadShortRight,
    /// Offset of StartingVpn.
    ///
    /// Since the size of the field may vary from a Windows version to another, #winKmFieldVadShortVpnSize should
    /// be checked in order to know how much to read from the guest.
    winKmFieldVadShortStartingVpn,
    /// Offset of StartingVpnHigh.
    ///
    /// Not all Windows versions have this. If it is 0, it is not used.
    winKmFieldVadShortStartingVpnHigh,
    /// Offset of EndingVpn.
    ///
    /// Since the size of the field may vary from a Windows version to another, #winKmFieldVadShortVpnSize should
    /// be checked in order to know how much to read from the guest.
    winKmFieldVadShortEndingVpn,
    /// Offset of EndingVpnHigh.
    ///
    /// Not all Windows versions have this. If it is 0, it is not used.
    winKmFieldVadShortEndingVpnHigh,
    /// Offset of VadFlags.
    ///
    /// The size of the field varies. Check #winKmFieldVadShortFlagsSize in order to know the valid size.
    winKmFieldVadShortFlags,
    /// The minimum size that must be read from the guest in order to properly parse #winKmFieldVadShortFlags.
    winKmFieldVadShortFlagsSize,
    /// The size of #winKmFieldVadShortStartingVpn and #winKmFieldVadShortEndingVpn.
    ///
    /// #winKmFieldVadShortStartingVpnHigh and #winKmFieldVadShortEndingVpnHigh are always 1 in size.
    winKmFieldVadShortVpnSize,
    /// The minimum size that must be read from the guest in order to properly parse a _MMVAD_SHORT structure.
    winKmFieldVadShortSize,
    /// @brief  The end of the fields
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries
    winKmFieldVadShortEnd
} WIN_KM_FIELD_VAD_SHORT;

///
/// @brief   Indexes in the WIN_OPAQUE_FIELDS.Km.VadLong array, containing information about the _MMVAD_LONG
/// structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_VAD_LONG
{
    winKmFieldVadLongSubsection = 0,    ///< Offset of Subsection.
    /// @brief  The end of the fields
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries
    winKmFieldVadLongEnd
} WIN_KM_FIELD_VAD_LONG;

///
/// @brief   Indexes in the WIN_OPAQUE_FIELDS.Km.VadFlags array, containing information about the bits in the
/// #winKmFieldVadShortFlags field.
/// @ingroup    group_guest_support
///
/// Certain values are parsed by shifting the flags value and then applying a mask, while boolean values are stored
/// as the bit that must be checked in order to know if that bit is set or not.
/// For example, in order to obtain the type from a 32-bit flags value you need to:
/// @code
///     DWORD flags = ...
///     VAD_TYPE = (flags >> WIN_KM_FIELD(VadFlags, TypeShift)) & WIN_KM_FIELD(VadFlags, TypeMask);
/// @endcode
/// While checking if private fix-up is set:
/// @code
///     DWORD flags = ...
///     BOOLEAN privateFixup = 0 != (flags & WIN_KM_FIELD(VadFlags, PrivateFixupMask));
/// @endcode
///
/// The #WIN_KM_FIELD macro can be used to access these more easily.
typedef enum _WIN_KM_FIELD_VADFLAGS
{
    /// The right shift that must be applied to the flags field before applying the #winKmFieldVadFlagsTypeMask mask
    /// in order to obtain the Type value.
    winKmFieldVadFlagsTypeShift = 0,
    /// The mask that must be applied in order to obtain the Type value.
    ///
    /// The flags value must first be right shifted with #winKmFieldVadFlagsTypeShift.
    winKmFieldVadFlagsTypeMask,

    /// The right shift that must be applied to the flags field before applying the #winKmFieldVadFlagsProtectionMask
    /// mask in order to obtain the Protection value.
    winKmFieldVadFlagsProtectionShift,
    /// The mask that must be applied in order to obtain the Protection value.
    ///
    /// The flags value must first be right shifted with #winKmFieldVadFlagsProtectionShift.
    winKmFieldVadFlagsProtectionMask,

    /// The index of the NoChange bit.
    ///
    /// Since this can be in the upper 32-bits of a 64-bit value and CAMI can not send 64-bit values, it is stored
    /// as the bit index. For example:
    /// @code
    ///     QWORD flags = ...
    ///     BOOLEAN noChange = 0 != (flags & BIT(WIN_KM_FIELD(VadFlags, NoChangeBit)));
    /// @endcode
    winKmFieldVadFlagsNoChangeBit,

    /// The mask that must be applied for the private fix-up setting.
    winKmFieldVadFlagsPrivateFixupMask,

    /// The mask for the DeleteInProgressBit.
    ///
    /// Not all Windows versions use this. If it is not used it is 0.
    winKmFieldVadFlagsDeleteInProgressMask,

    /// @brief  The end of the fields
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries
    winKmFieldVadFlagsEnd
} WIN_KM_FIELD_VADFLAGS;

///
/// @brief Indexes in the WIN_OPAQUE_FIELDS.Km.SyscallNumbers array, containing syscall numbers.
/// @ingroup    group_guest_support
///
/// The #WIN_SYSCALL_NUMBER or #WIN_KM_FIELD macros can be used to access these more easily.
typedef enum _WIN_KM_FIELD_SYSCALL_NUMBERS
{
    winKmFieldSyscallNumbersNtWriteVirtualMemory = 0,   ///< The NtWriteSyscallMemory syscall number.
    winKmFieldSyscallNumbersNtProtectVirtualMemory,     ///< The NtProtectVirtualMemory syscall number.
    winKmFieldSyscallNumbersNtCreateThreadEx,           ///< The NtCreateThreadEx syscall number.
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldSyscallNumbersEnd
} WIN_KM_FIELD_SYSCALL_NUMBERS;

///
/// @brief  Indexes in the WIN_OPAQUE_FIELDS.Km.FileObject array, containing information about the _FILE_OBJECT
/// structure.
/// @ingroup    group_guest_support
///
/// The #WIN_KM_FIELD macros can be used to access these more easily.
typedef enum _WIN_KM_FIELD_FILE_OBJECT
{
    winKmFieldFileObjectNameBuffer, ///< Offset of FileName.Buffer
    winKmFieldFileObjectNameLength, ///< Offset of FileName.Length
    /// @brief  The end of the fields.
    ///
    /// This must always be the last entry in this enum. New entries must be added right before this one in order to
    /// preserve the existing order of entries.
    winKmFieldFileObjectEnd
} WIN_KM_FIELD_FILE_OBJECT;

///
/// @brief  Contains information about various Windows user mode and kernel mode structures.
/// @ingroup    group_guest_support
///
/// Everything about a structure of interest should be placed here (size, field offsets, etc).
/// The Km structure contains information about kernel objects, while the Um field contains information about
/// user mode objects.
/// Each structure has a specific tag (#WIN_KM_STRUCTURE for Km, #WIN_UM_STRUCTURE for Um) which is used to
/// identify it.
/// Each entry inside an array contains specific information. The specific WIN_UM_FIELD and WIN_KM_FIELD structures
/// describe the information found at each index in these arrays. For example, the #WIN_KM_FIELD_PROCESS enum describes
/// the information found in the Km.Process array. If the offset at which the name of a process is found inside the
/// kernel _EPROCESS structure is needed, it can be obtained by looking at Km.Process[#winKmFieldProcessName]. In
/// order to simplify this, the #WIN_KM_FIELD macro can be used: WIN_OPAQUE_FIELDS(Process, Name). A similar approach
/// is available for user mode fields with the #WIN_UM_FIELD macro.
/// These fields are set when a CAMI file is loaded at initialization time, in the #IntCamiLoadOpaqueFields function.
/// If the loaded CAMI file contains a structure that is not known by introcore, or contains more field than the
/// current introcore version uses, the extra information is discarded. This is why new fields should be added right
/// before the End tags, in order to preserve the current order and allow older introcore versions to load newer
/// CAMI files.
///
typedef struct _WIN_OPAQUE_FIELDS
{
    /// @brief  Kernel mode information.
    struct
    {
        /// Information about the _EPROCESS structure. Indexed with values from #WIN_KM_FIELD_PROCESS.
        DWORD Process[winKmFieldProcessEnd];
        /// Information about the _ETHREAD structure. Indexed with values from #WIN_KM_FIELD_THREAD.
        DWORD Thread[winKmFieldThreadEnd];
        /// Information about the _DRIVER_OBJECT structure. Indexed with values from #WIN_KM_FIELD_DRVOBJ.
        DWORD DrvObj[winKmFieldDrvObjEnd];
        /// Information about the _KPCR structure. Indexed with values from #WIN_KM_FIELD_PCR.
        DWORD Pcr[winKmFieldPcrEnd];
        /// Information about the _POOL_DESCRIPTOR structure. Indexed with values from #WIN_KM_FIELD_POOLDESCRIPTOR.
        DWORD PoolDescriptor[winKmFieldPoolDescriptorEnd];
        /// Information about the _MMPFN structure. Indexed with values from #WIN_KM_FIELD_MMPFN.
        DWORD Mmpfn[winKmFieldMmpfnEnd];
        /// Information about the _TOKEN structure. Indexed with values from #WIN_KM_FIELD_TOKEN.
        DWORD Token[winKmFieldTokenEnd];
        /// Information about the various structures and kernel data. Indexed with values from #WIN_KM_FIELD_UNGROUPED.
        DWORD Ungrouped[winKmFieldUngroupedEnd];
        /// Information about the _EPROCESS flags. Indexed with values from #WIN_KM_FIELD_EPROCESSFLAGS.
        DWORD EprocessFlags[winKmFieldEprocessFlagsEnd];
        /// Information about the _MMVAD_SHORT structure. Indexed with values from #WIN_KM_FIELD_VAD_SHORT.
        DWORD VadShort[winKmFieldVadShortEnd];
        /// Information about the _MMVAD_LONG structure. Indexed with values from #WIN_KM_FIELD_VAD_LONG.
        DWORD VadLong[winKmFieldVadLongEnd];
        /// Information about the _MMVAD_SHORT flags. Indexed with values from #WIN_KM_FIELD_VADFLAGS.
        DWORD VadFlags[winKmFieldVadFlagsEnd];
        /// Syscall numbers needed by agents. Indexed with values from #WIN_KM_FIELD_SYSCALL_NUMBERS.
        DWORD SyscallNumbers[winKmFieldSyscallNumbersEnd];
        /// Information about the _FILE_OBJECT structure. Indexed with values from #WIN_KM_FIELD_FILE_OBJECT.
        DWORD FileObject[winKmFieldFileObjectEnd];
    } Km;

    /// @brief  User mode information.
    struct
    {
        /// Information about the _LDR_DATA_TABLE_ENTRY structure. Indexed with values from #WIN_UM_FIELD_DLL.
        DWORD Dll[winUmFieldDllEnd];
        /// Information about the _PEB structure. Indexed with values from #WIN_UM_FIELD_PEB.
        DWORD Peb[winUmFieldPebEnd];
        /// Information about the _TEB structure. Indexed with values from #WIN_UM_FIELD_TEB.
        DWORD Teb[winUmFieldTebEnd];
    } Um;
} WIN_OPAQUE_FIELDS, *PWIN_OPAQUE_FIELDS;

///
/// @brief  Macro used to access kernel mode fields inside the #WIN_OPAQUE_FIELDS structure.
/// @ingroup    group_guest_support
///
/// @param[in]  Structure   The structure name. This is identical to the name of the array in the
///                         #WIN_OPAQUE_FIELDS.Km structure which contains the needed information.
/// @param[in]  Field       The name of the field. For example, if the value of the #winKmFieldProcessName field
///                         is needed, this will simply be Field.
///
/// @returns    The value of the requested field.
///
/// @remarks    This is a handy macro, allowing for more concise and expressive code when accessing the opaque
///             kernel information. For example:
/// @code
///     procNameOffset = gWinGuest->OsSpecificFields.Km.Process[winKmFieldProcessName];
///     procNameOffset = WIN_KM_FIELD(Process, Name);
/// @endcode
///
#define WIN_KM_FIELD(Structure, Field) gWinGuest->OsSpecificFields.Km.Structure[winKmField##Structure##Field]

///
/// @brief  Macro used to access syscall numbers from inside the #WIN_OPAQUE_FIELDS structure.
/// @ingroup    group_guest_support
///
/// @param[in]  Syscall     The syscall name. For example, if the value of #winKmFieldSyscallNumbersNtCreateThreadEx is
///                         is needed, this will simply be NtCreateThreadEx.
///
/// @returns    The requested syscall number.
///
/// @remarks    This is a handy macro, allowing for more concise and expressive code when accessing the opaque
///             kernel information. For example:
/// @code
///     sysNo = gWinGuest->OsSpecificFields.Km.SyscallNumbers[winKmFieldNtCreateThreadEx];
///     sysNo = WIN_SYSCALL_NUMBER(NtCreateThreadEx);
/// @endcode
///
#define WIN_SYSCALL_NUMBER(Syscall) WIN_KM_FIELD(SyscallNumbers, Syscall)

///
/// @brief  Macro used to access user mode fields inside the #WIN_OPAQUE_FIELDS structure.
/// @ingroup    group_guest_support
///
/// @param[in]  Structure   The structure name. This is identical to the name of the array in the
///                         #WIN_OPAQUE_FIELDS.Um structure which contains the needed information.
/// @param[in]  Field       The name of the field. For example, if the value of the #winUmFieldTebWow64SaveArea
///                         field is needed, this will simply be Wow64SaveArea.
///
/// @returns    The value of the requested field.
///
/// @remarks    This is a handy macro, allowing for more concise and expressive code when accessing the opaque
///             user information. For example:
/// @code
///     wow64SaveAreaOffset = gWinGuest->OsSpecificFields.Um.Teb[winUmFieldTebWow64SaveArea];
///     wow64SaveAreaOffset = WIN_UM_FIELD(Teb, Wow64SaveArea);
/// @endcode
///
#define WIN_UM_FIELD(Structure, Field) gWinGuest->OsSpecificFields.Um.Structure[winUmField##Structure##Field]

///
/// @brief  Information that can identify a module.
///
/// This can be used to obtain a PDB for a module.
///
typedef struct _WIN_MODULE_UNIQUE_KEY
{
    DWORD ImageSize;        ///< The size of image, as taken from the MZPE headers.
    DWORD TimeDateStamp;    ///< The time date stamp of the image, as taken from the MZPE headers.
} WIN_MODULE_UNIQUE_KEY, PWIN_MODULE_UNIQUE_KEY;

///
/// @brief  The type of the Windows OS.
///
/// This is equivalent to the _NT_PRODUCT_TYPE enum found inside the Windows kernel.
typedef enum
{
    winProductTypeNotYetLoaded, ///< Information not yet loaded.
    winProductTypeWinNt,        ///< Workstation.
    winProductTypeLanManNt,     ///< Advanced server.
    winProductTypeServer,       ///< Server.
    /// @brief  The product type is unknown.
    ///
    /// Usually this means that the product information could not be obtained or that it is not valid.
    winProductTypeUnknown
} WIN_PRODUCT_TYPE;

///
/// @brief  Holds information about a Windows guest.
///
typedef struct _WINDOWS_GUEST
{
    QWORD PsCreateSystemThread;         ///< Guest virtual address of the PsCreateSystemThread kernel function.
    QWORD ExAllocatePoolWithTag;        ///< Guest virtual address of the ExAllocatePoolWithTag kernel function.
    QWORD ExFreePoolWithTag;            ///< Guest virtual address of the ExFreePoolWithTag kernel function.
    QWORD SyscallAddress;               ///< Guest virtual address of the SYSCALL/SYSENTER handler.
    DWORD NtBuildNumberValue;           ///< The value of the NtBuildNumber kernel variable.
    QWORD KeServiceDescriptorTable;     ///< Guest virtual address of the KeServiceDescriptorTable variable.
    QWORD Ssdt;                         ///< Guest virtual address of the SSDT structure inside the kernel.
    DWORD NumberOfServices;             ///< The number of entries in the SSDT.
    QWORD HalpInterruptControllerGva;   ///< Guest virtual address of the HalpInterruptController (owned by hal.dll).
    QWORD PropperSyscallGva;            ///< Guest virtual address of the KiSystemServiceUser function.

    PCHAR NtBuildLabString;             ///< A NULL terminated string containing the NtBuildLab kernel variable.
    /// @brief  A NULL terminated string containing Windows version information.
    ///
    /// This is obtained from a CAMI file and is set by #IntCamiLoadWindows.
    PCHAR VersionString;
    /// @brief  A NULL terminated string containing Windows server version information.
    ///
    /// This is obtained from a CAMI file and is set by #IntCamiLoadWindows.
    PCHAR ServerVersionString;

    WIN_PRODUCT_TYPE ProductType;       ///< The product type. Obtained directly from the guest during initialization.

    QWORD PsActiveProcessHead;          ///< Guest virtual address of the PsActiveProcessHead kernel variable.
    QWORD PsLoadedModuleList;           ///< Guest virtual address of the PsLoadedModuleList kernel variable.
    QWORD MmPfnDatabase;                ///< Guest virtual address of the PFN data base.
    QWORD ObpRootDirectoryObject;       ///< Guest virtual address of the ObpRootDirectoryObject.
    QWORD DriverDirectory;              ///< Guest virtual address of the Driver namespace directory.
    QWORD FileSystemDirectory;          ///< Guest virtual address of the FileSystem namespace directory.

    /// @brief  A buffer containing the entire kernel image.
    ///
    /// It can be used instead of reading from the guest memory when values from non-writable parts of the kernel
    /// are needed. This boosts performance, as it can save us from quite a lot of GVA to GPA translations and GPA
    /// mappings inside the host.
    /// Because certain parts of the kernel may be swapped out, this buffer is filled using IntSwapMemRead, with
    /// #IntWinGuestSectionInMemory as the swap in handler. This means that it is not necessarily read in a
    /// sequential manner. While #RemainingSections is not 0, the buffer is not yet filled and no hooks are placed
    /// inside the guest. It is guaranteed that the buffer is fully read after #IntWinGuestFinishInit is called.
    BYTE *KernelBuffer;
    DWORD KernelBufferSize;             ///< The size of the #KernelBuffer.

    DWORD RemainingSections;            ///< The number of kernel sections not yet read into #KernelBuffer.
    LIST_HEAD InitSwapHandles;          ///< A list of swap handles used to read #KernelBuffer.

    WIN_OPAQUE_FIELDS OsSpecificFields; ///< OS-dependent and specific information (variables, offsets, etc).
} WINDOWS_GUEST, *PWINDOWS_GUEST;

///
/// @brief  The initialization swap handle.
///
/// These are used to read #WINDOWS_GUEST.KernelBuffer.
///
typedef struct _WIN_INIT_SWAP
{
    LIST_ENTRY  Link;               ///< Link inside the #WINDOWS_GUEST.InitSwapHandles list.
    void        *SwapHandle;       ///< The actual swap handle returned by IntSwapMemRead.

    QWORD       VirtualAddress;     ///< The guest virtual address that will be read.
    DWORD       Size;               ///< The size of the read.
} WIN_INIT_SWAP, *PWIN_INIT_SWAP;

INTSTATUS
IntWinGuestNew(
    void
    );

INTSTATUS
IntWinGuestInit(
    void
    );

void
IntWinGuestUninit(
    void
    );

void
IntWinGuestCancelKernelRead(
    void
    );

INTSTATUS
IntWinGetVersionString(
    _In_ DWORD FullStringSize,
    _In_ DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    );

#endif // _WINGUEST_H_
