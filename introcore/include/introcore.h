/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTROCORE_H_
#define _INTROCORE_H_

#include "introcrt.h"
#include "dumper.h"
#include "stats.h"

/// @brief      If set, matching functions like #IntMatchPatternUtf8 will match up until the first wild char encountered
#define INTRO_MATCH_TRUNCATED 0x00000001

extern void *gLock;
extern void *gIntHandle;

extern INTRO_ERROR_CONTEXT gErrorContext;

extern const QWORD gByteMaskToBitMask[256];

extern BOOLEAN gAbortLoad;

extern QWORD gEventId;


///
/// @brief          Initializes a #RBTREE structure
///
/// @param[in, out] Name    The #RBTREE structure to be initialized
/// @param[in]      Free    The #PFUNC_RbTreeNodeFree function used to cleanup the tree. Called by #RbUninit for each
///                         node in the tree
/// @param[in]      Compare The #PFUNC_RbTreeNodeCompare used to compare elements of the tree. Used by #RbSearch and
///                 #RbInsertNode
///
/// @post   The #RBTREE structure is initialized. It will contain no entries and will use Free and Compare as the
///         cleanup and compare routines.
///
#define RB_TREE_INIT(Name, Free, Compare)       \
    {                                           \
        &((Name).Nil),                          \
        {                                       \
            &((Name).Nil),                      \
            &((Name).Nil),                      \
            &((Name).Nil),                      \
            ncBlack                             \
        },                                      \
        Free,                                   \
        Compare,                                \
        0                                       \
    }


/// @brief      Minimum amount of free heap needed in order to activate process protection
#ifdef USER_MODE
# define MIN_HEAP_SIZE_PERCENT       (20)
#else
# define MIN_HEAP_SIZE_PERCENT       (30)
#endif

#define MAX_TRANSLATION_DEPTH     5 ///< Maximum depth of the translation hierarchy

///
/// @brief      Paging modes
///
typedef enum
{
    PAGING_NONE = 0,        ///< No paging
    PAGING_NORMAL_MODE,     ///< 32-bit paging
    PAGING_PAE_MODE,        ///< 32-bit paging with PAE
    PAGING_4_LEVEL_MODE,    ///< 4-level paging
    PAGING_5_LEVEL_MODE,    ///< 5-level paging
} PAGING_MODE;

///
/// @defgroup   group_translation_flags Translation flags
/// @brief      Options that control the way a memory translation is done
/// @ingroup    group_internal
/// @{
///

#define TRFLG_NONE                      0x00000000  ///< No special options
#define TRFLG_CACHING_ATTR              0x00000001  ///< Obtain caching information from the guest's IA32_PAT MSR
#define TRFLG_NORMAL_MODE               0x10000000  ///< Hint that the paging mode is #PAGING_NORMAL_MODE
#define TRFLG_PAE_MODE                  0x20000000  ///< Hint that the paging mode is #PAGING_PAE_MODE
#define TRFLG_4_LEVEL_MODE              0x30000000  ///< Hint that the paging mode is #PAGING_4_LEVEL_MODE
#define TRFLG_5_LEVEL_MODE              0x40000000  ///< Hint that the paging mode is #PAGING_5_LEVEL_MODE
#define TRFLG_MODE_MASK                 0xF0000000  ///< Mask used to isolate only the paging mode flags
#define TRFLG_ALL                       (TRFLG_CACHING_ATTR)    ///< All translation flags, excluding the paging mode

/// @brief  Obtains the translation mode flag for the currently used paging mode
#define TRFLG_PG_MODE                   (gGuest.LA57 ? TRFLG_5_LEVEL_MODE : \
                                         gGuest.Guest64 ? TRFLG_4_LEVEL_MODE : \
                                         gGuest.PaeEnabled ? TRFLG_PAE_MODE : \
                                                             TRFLG_NORMAL_MODE)

/// @}

///
/// @brief  Encapsulates information about a virtual to physical memory translation
///
typedef struct _VA_TRANSLATION
{
    /// @brief  The translated virtual address
    QWORD               VirtualAddress;
    /// @brief  The physical address to which VirtualAddress translates to
    QWORD               PhysicalAddress;
    /// @brief  Contains the physical address of each entry within the translation tables
    ///
    /// Contains #MappingsCount entries, with the entry at index 0 being the address of the root table
    QWORD               MappingsTrace[MAX_TRANSLATION_DEPTH];
    /// @brief  Contains the entry in which paging table
    ///
    /// Contains #MappingsCount entries, with the entry at index 0 being the entry in the root table
    QWORD               MappingsEntries[MAX_TRANSLATION_DEPTH];
    /// @brief  The entry that maps #VirtualAddress to #PhysicalAddress, together with all the control bits
    ///
    /// This is the entry in the last table.
    QWORD               Flags;

    QWORD               PageSize;       ///< The page size used for this translation
    QWORD               Cr3;            ///< The Cr3 used for this translation
    DWORD               MappingsCount;  ///< The number of entries inside the #MappingsTrace and #MappingsEntries arrays
    BOOLEAN             Pointer64;      ///< True if #VirtualAddress is a 64-bit address
    /// @brief  True if this page is accessible to user mode code
    ///
    /// This happens when the user/supervisor bit is set in all page table entries in the mapping hierarchy
    BOOLEAN             IsUser;
    /// @brief  True if this page is writable
    ///
    /// This happens when the write bit is set in all page table entries in the mapping hierarchy
    BOOLEAN             IsWritable;
    /// @brief  True if this page is executable
    ///
    /// This happens if the NX bit is not set in all page table entries in the mapping hierarchy
    BOOLEAN             IsExecutable;
    /// @brief  The paging mode used for this translation
    ///
    /// This is one of the #PAGING_MODE values
    PAGING_MODE         PagingMode;
    /// @brief  The caching attributes used for this translation
    ///
    /// These are obtained from the guest IA32_PAT MSR.
    BYTE                CachingAttribute;
} VA_TRANSLATION, *PVA_TRANSLATION;

void
IntPreinit(
    void
    );

INTSTATUS
IntInit(
    _Inout_ GLUE_IFACE *GlueInterface,
    _In_ UPPER_IFACE const *UpperInterface
    );

INTSTATUS
IntUninit(
    void
    );

INTSTATUS
IntVirtMemRead(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    );

INTSTATUS
IntVirtMemWrite(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_reads_bytes_(Length) void *Buffer
    );

INTSTATUS
IntKernVirtMemRead(
    _In_ QWORD KernelGva,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    );

INTSTATUS
IntKernVirtMemWrite(
    _In_ QWORD KernelGva,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    );

INTSTATUS
IntVirtMemSet(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_ BYTE Value
    );

INTSTATUS
IntPhysicalMemRead(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    );

INTSTATUS
IntPhysicalMemWrite(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    );

INTSTATUS
IntPhysicalMemReadAnySize(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    );

INTSTATUS
IntPhysicalMemWriteAnySize(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    );

INTSTATUS
IntKernVirtMemFetchQword(
    _In_ QWORD GuestVirtualAddress,
    _Out_ QWORD *Data
    );

INTSTATUS
IntKernVirtMemFetchDword(
    _In_ QWORD GuestVirtualAddress,
    _Out_ DWORD *Data
    );

INTSTATUS
IntKernVirtMemFetchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _Out_ void *Data
    );

INTSTATUS
IntVirtMemFetchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ QWORD *Data
    );

INTSTATUS
IntVirtMemFetchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ DWORD *Data
    );

INTSTATUS
IntVirtMemFetchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ void *Data
    );

INTSTATUS
IntKernVirtMemPatchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_ QWORD Data
    );

INTSTATUS
IntKernVirtMemPatchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD Data
    );

INTSTATUS
IntKernVirtMemPatchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_ QWORD Data
    );

INTSTATUS
IntVirtMemPatchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ QWORD Data
    );

INTSTATUS
IntVirtMemPatchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ DWORD Data
    );

INTSTATUS
IntVirtMemPatchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ QWORD Data
    );

INTSTATUS
IntVirtMemFetchString(
    _In_ QWORD Gva,
    _In_ DWORD MaxLength,
    _In_opt_ QWORD Cr3,
    _Out_writes_z_(MaxLength) void *Buffer
    );

INTSTATUS
IntTranslateVirtualAddressEx(
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ DWORD Flags,
    _Out_ VA_TRANSLATION *Translation
    );

INTSTATUS
IntTranslateVirtualAddress(
    _In_ QWORD Gva,
    _In_opt_ QWORD Cr3,
    _Out_ QWORD *PhysicalAddress
    );

__must_check
INTSTATUS
IntVirtMemMap(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    );

INTSTATUS
IntVirtMemUnmap(
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    );

INTSTATUS
IntInjectExceptionInGuest(
    _In_ BYTE Vector,
    _In_ QWORD Cr2,
    _In_ DWORD ErrorCode,
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntPauseVcpus(
    void
    );

INTSTATUS
IntResumeVcpus(
    void
    );

void
IntEnterDebugger2(
    _In_ PCHAR File,
    _In_ DWORD Line
    );

#define IntEnterDebugger()      IntEnterDebugger2(__FILE__, __LINE__)

void
IntDbgEnterDebugger2(
    _In_ PCHAR File,
    _In_ DWORD Line
    );

#define IntDbgEnterDebugger()   IntDbgEnterDebugger2(__FILE__, __LINE__)

INTSTATUS
IntGuestUninitOnBugcheck(
    _In_ void const *Detour
    );

//
// Internal API
//
BOOLEAN
IntMatchPatternUtf8(
    _In_z_ const CHAR *Pattern,
    _In_z_ const CHAR *String,
    _In_ DWORD Flags
    );

BOOLEAN
IntMatchPatternUtf16(
    _In_z_ const WCHAR *Pattern,
    _In_z_ const WCHAR *String,
    _In_ DWORD Flags
    );

BOOLEAN
IntPolicyProcIsBeta(
    _In_opt_ const void *Process,
    _In_ QWORD Flag
    );

BOOLEAN
IntPolicyCoreIsOptionBeta(
    _In_ QWORD Flag
    );

BOOLEAN
IntPolicyProcIsFeedback(
    _In_opt_ const void *Process,
    _In_ QWORD Flag
    );

QWORD
IntPolicyGetProcProt(
    _In_opt_ const void *Process
    );

BOOLEAN
IntPolicyCoreTakeAction(
    _In_ QWORD Flag,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ INTRO_ACTION_REASON *Reason
    );

BOOLEAN
IntPolicyProcTakeAction(
    _In_ QWORD Flag,
    _In_ void const *Process,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ INTRO_ACTION_REASON *Reason
    );

BOOLEAN
IntPolicyProcForceBetaIfNeeded(
    _In_ QWORD Flag,
    _In_ void *Process,
    _Inout_ INTRO_ACTION *Action
    );

BOOLEAN
IntPolicyCoreForceBetaIfNeeded(
    _In_ QWORD Flag,
    _Inout_ INTRO_ACTION *Action
    );

BOOLEAN
IntPolicyIsCoreOptionFeedback(
    _In_ QWORD Flag
    );

char *
utf16_for_log(
    _In_z_ const WCHAR *WString
    );


INTSTATUS
IntReadString(
    _In_ QWORD StrGva,
    _In_ DWORD MinimumLength,
    _In_ BOOLEAN AnsiOnly,
    _Inout_ char **String,
    _Out_opt_ DWORD *StringLength
    );

#endif // _INTROCORE_H_
