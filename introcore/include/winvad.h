/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINVAD_H_
#define _WINVAD_H_

#include "detours.h"
#include "winprocess.h"

/// One of the Introcore VAD protection constants. This means that the page is readable.
#define PROT_READ 1
/// One of the Introcore VAD protection constants. This means that the page is writable.
#define PROT_WRITE 2
/// One of the Introcore VAD protection constants. This means that the page is executable.
#define PROT_EXEC 4

///
/// @brief      VAD protection flags as used by the Windows kernel. These represent the values in the Protection
/// portion of the VadFlags field inside a _MMVAD_SHORT structure.
///
/// Note that these are bit flags and valid values can be constructing by combining these, so valid values extend
/// past this enum.
typedef enum
{
    VAD_PROT_NOACCESS = 0x0000,
    VAD_PROT_READONLY = 0x0001,
    VAD_PROT_EXECUTE = 0x0002,
    VAD_PROT_EXECUTE_READ = 0x0003,
    VAD_PROT_READWRITE = 0x0004,
    VAD_PROT_WRITECOPY = 0x0005,
    VAD_PROT_EXECUTE_READWRITE = 0x0006,
    VAD_PROT_EXECUTE_WRITECOPY = 0x0007,
    VAD_PROT_NOCACHE = 0x0008,
    VAD_PROT_GUARD = 0x0010,
    VAD_PROT_WRITECOMBINE = 0x0020,
} WIN_VAD_PROT;

///
/// @brief  A representation of a memory page included in a VAD structure.
typedef struct _VAD_PAGE
{
    /// The base address of the page.
    QWORD       Address;

    /// The protection flags used by Windows for this page.
    ///
    /// These are the protection flags used by the entire VAD and set when the VAD was created.
    /// See https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants for possible values.
    DWORD       VmProtection;
    /// The protection flags as used by Introcore.
    ///
    /// This is obtained by converting VmProtection to a combination of #PROT_READ, #PROT_WRITE, and #PROT_EXEC.
    DWORD       Protection;

    /// The VAD containing this page.
    struct _VAD *Vad;
    /// Execution hook handle, if one exists.
    void        *ExecHook;

    /// The first page in the memory range to which this page belongs. This is always inside the limits of the VAD.
    ///
    /// Initially, the range is the entire VAD, bur operations that change individual page permissions (for example,
    /// the VirtualProtect guest API) will create sub-ranges inside the VAD.
    QWORD       RangeStart;
    /// The last page in the memory range to which this page belongs. This is always inside the limits of the VAD.
    ///
    /// Initially, the range is the entire VAD, bur operations that change individual page permissions (for example,
    /// the VirtualProtect guest API) will create sub-ranges inside the VAD.
    QWORD       RangeEnd;

    /// True if an execution from this page was attempted and it was deemed to no be malicious.
    BOOLEAN     Legitimate;
} VAD_PAGE, *PVAD_PAGE;

///
/// @brief  A representation of a Windows VAD structure.
///
/// This can be obtained from a _MMVAD_SHORT or a _MMVAD_LONG Windows structure.
typedef struct _VAD
{
    /// The node inside the #WIN_PROCESS_OBJECT.VadTree tree.
    RBNODE RbNode;
    /// The left node at the moment the VAD was read from the guest.
    ///
    /// This might change, so don't count on it, except after it was read and the guest was not applying changes
    /// to the tree. We need it when parsing the in-guest tree.
    QWORD Left;
    /// The right node at the moment the VAD was read from the guest.
    ///
    /// This might change, so don't count on it, except after it was read and the guest was not applying changes
    /// to the tree. We need it when parsing the in-guest tree.
    QWORD Right;
    /// The parent node at the moment the VAD was read from the guest.
    ///
    /// This might change, so don't count on it, except after it was read and the guest was not applying changes
    /// to the tree. We need it when parsing the in-guest tree.
    QWORD Parent;
    /// The first page in the VAD.
    ///
    /// The [StartPage, EndPage] range is always inclusive.
    QWORD StartPage;
    /// The last page in the VAD.
    ///
    /// The [StartPage, EndPage] range is always inclusive.
    QWORD EndPage;
    /// The guest virtual address at which the corresponding Windows _MMVAD structure is located.
    QWORD VadGva;
    /// The number of 4K pages in the VAD.
    QWORD PageCount;
    /// The protection as represented inside the Windows kernel. This is obtained from the Protection portion of the
    /// VadFlags field inside the _MMVAD_SHORT Windows structure.
    ///
    /// This represents the protection rights passed when the VAD was created. Protection changes done after that are
    /// reflected in the corresponding #VAD_PAGE. Valid values are a combination of #WIN_VAD_PROT values.
    DWORD VadProtection;
    /// The type of the VAD.
    VAD_TYPE VadType;
    /// VAD protection as represented by Introcore.
    ///
    /// This represents the protection rights equivalent to VadProtection, valid for the original protection rights
    /// of the VAD. Changes done after the VAD was created are reflected in the corresponding #VAD_PAGE. Valid values
    /// are a combination of #PROT_READ, #PROT_WRITE, and #PROT_EXEC.
    DWORD Protection;

    /// The process to which this VAD belongs to.
    WIN_PROCESS_OBJECT *Process;
    /// An array representing each page in the VAD. It has PageCount entries.
    VAD_PAGE **VadPages;
    /// The #IntSwapMemReadData handle used to swap the path of the image mapped by this VAD.
    ///
    /// Note that not all VADs map a file. This is used only for #VadImageMap VADs.
    void *PathSwapHandle;

    /// The guest virtual address of the _SUBSECTION structure associated with a _MMVAD_LONG structure.
    ///
    /// This is valid only for VADs that have the Type #VadImageMap; will be 0 for other types. It is used by the
    /// #WINUM_PATH cache.
    QWORD SubsectionGva;

    /// The path of the image file mapped by this VAD.
    ///
    /// Will be NULL if it is not used. Can be non-NULL only if the VAD Type is #VadImageMap.
    WINUM_PATH *Path;

    /// The number of execution violations triggered by pages inside this VAD.
    DWORD ExecCount;

    struct
    {
        /// Set if the VAD was statically detected by a scan, after it was created.
        DWORD StaticScan : 1;
        /// Set if the memory range represented by this VAD is a stack.
        DWORD IsStack : 1;
        /// Set if the memory range represented by this VAD has a size of at least 4G.
        DWORD HugeVad : 1;
        /// Set if this VAD is not monitored regardless of the protection rights it has.
        DWORD IsIgnored : 1;
        /// Set if the NoChange bit inside the VadFlags field is set.
        DWORD NoChange : 1;
        /// Set if the PrivateFixup bit inside the VadFlags field is set.
        DWORD PrivateFixup : 1;
        /// Set if the DeleteInProgress bit inside the VadFlags field is set.
        DWORD DeleteInProgress : 1;
        /// Spare bits.
        DWORD Unused : 25;
    };
} VAD, *PVAD;

///
/// @brief      Callback type used for in-guest VAD tree traversals.
///
/// This will be invoked for every node in the tree.
///
/// @param[in]  VadNodeGva  The guest virtual address of the tree node for which this callback was invoked.
/// @param[in]  Level       The level at which this node is located inside the tree.
/// @param[in]  Context     Optional context passed by the caller.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value. Note that errors are
/// logged, but the status does not affect the iteration process in any way and errors are not propagated back to
/// the caller.
typedef INTSTATUS (*PFUNC_WinVadTraversalCallback)(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _In_opt_ void *Context
    );

void
IntWinVadProcessInit(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

VAD *
IntWinVadFindByVa(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD Va
    );

INTSTATUS
IntWinVadHandleInsert(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadHandleInsertPrivate(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadHandleInsertMap(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadHandleVirtualProtect(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadHandleDeleteVaRange(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadHandleFinishVadDeletion(
    _In_ void const *Detour
    );

INTSTATUS
IntWinVadImportProcessTree(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinVadRemoveProcessTree(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

void
IntWinVadStopExploitMonitor(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinVadShortDump(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _In_opt_ void *Context
    );

QWORD
IntWinVadFindNodeInGuestSpace(
    _In_ QWORD VadRoot,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _In_ DWORD Level,
    _In_ QWORD OldStartPage,
    _In_ BOOLEAN LastBranchRight
    );

INTSTATUS
IntWinVadInOrderRecursiveTraversal(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _In_ PFUNC_WinVadTraversalCallback Callback,
    _In_opt_ void *Context
    );

_Function_class_(FUNC_RbTreeWalkCallback)
BOOLEAN
IntWinVadDump(
    _In_ VAD const *Vad,
    _In_ void *Context
    );

INTSTATUS
IntWinVadWalkTree(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PFUNC_RbTreeWalkCallback Callback
    );

INTSTATUS
IntWinVadHandleCommit(
    _In_ void const *Detour
    );

VAD *
IntWinVadFindAndUpdateIfNecessary(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD StartHint,
    _In_ QWORD LengthHint
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinPatchVadHandleCommit(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

BOOLEAN
IntWinVadIsInTree(
    _In_ const VAD *Vad
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsertPrivate(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsertMap(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchVirtualProtect(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchDeleteVaRange(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchFinishVadDeletion(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsert(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinVadProcImportMainModuleVad(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

void
IntWinVadDestroyObject(
    _Inout_ VAD **Vad
    );

INTSTATUS
IntWinVadFetchByRange(
    _In_ QWORD VadRoot,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _Out_ VAD *Vad
    );

#endif
