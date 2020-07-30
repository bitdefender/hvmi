/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_H_
#define _HOOK_H_

#include "introtypes.h"


///
/// Context types - each hook type has a dedicated constant. Creating a new hook system requires that you also
/// create a dedicated hook type.
///
enum _HOOK_TYPE
{
    hookTypeGpa = 1,    ///< Used by GPA hooks.
    hookTypeGva,        ///< Used by GVA hooks.
    hookTypePts,        ///< Used by page-table hooks.
    hookTypePtsPt,      ///< Used by an internal page monitored using PTS.
    hookTypePtm,        ///< Used by the internal page monitor (used by PTS).
    hookTypePtmPt,      ///< Used by an internal page monitored using PTM.
    hookTypeRegion,     ///< An entire hook region, consisting of multiple GVA hooks.
};

///
/// @defgroup   group_ept_hook_flags EPT Hook flags
/// @brief      Options that control the way EPT hooks are placed
/// @ingroup    group_internal
/// @{
///

/// @brief Global flags must be defined here and must be handled by each hooks layer (even if it ignores them, but it
/// must not define or use hooks that overlap existing global hooks).
#define HOOK_FLG_GLOBAL_MASK            0xFFFF0000

/// @brief Local flags are reserved for internal use inside each hook layer. These flags must not be propagated from
/// one layer to another, as they have different meaning between different hook layers.
#define HOOK_FLG_INTERNAL_MASK          0x0000FFFF

// Global flags, used for each kind of hook. The lower 16 bits are used by each hook subsystem individually.

/// @brief If flag is set, the hook has been removed, and waits the next commit to be actually deleted.
#define HOOK_FLG_REMOVE                 0x80000000
/// @brief If flag is set, the hook is disabled, therefore ignored on EPT violations.
#define HOOK_FLG_DISABLED               0x40000000
/// @brief If flag is set, then we won't remove the hook on commit phase; we'll let the parent hook handle the delete.
#define HOOK_FLG_CHAIN_DELETE           0x20000000
#define HOOK_FLG_PAGING_STRUCTURE       0x08000000  ///< If flag is set, the hook is set on paging structures.
#define HOOK_FLG_PAE_ROOT               0x04000000  ///< If flag is set, the hook is set on the 4 PDPTEs used on PAE.
/// @brief If flag is set, the hook is set on the root paging structure, and only the low, user-mode entires are hooked.
#define HOOK_FLG_PT_UM_ROOT             0x02000000
/// @brief If flag is set, the callback associated to this hook will have a higher priority than the others.
#define HOOK_FLG_HIGH_PRIORITY          0x01000000

/// Any of these flags set indicates that we are dealing with a page table page.
#define HOOK_PAGE_TABLE_FLAGS           (HOOK_FLG_PAGING_STRUCTURE|HOOK_FLG_PAE_ROOT|HOOK_FLG_PT_UM_ROOT)

/// @}


///
/// General hook header. A hook header must precede each hook type, especially if chaining is needed.
///
typedef struct _HOOK_HEADER
{
    DWORD               Flags;          ///< Generic flags. Check out @ref group_ept_hook_flags.
    BYTE                HookType;       ///< The type of the hook structure (see #_HOOK_TYPE)
    BYTE                EptHookType;    ///< The type of the hook in EPT (see #IG_EPT_HOOK_TYPE)
    BYTE                _Reserved[2];

    /// @brief The parent hook. For a GPA hook, for example, a GVA hook or a PagedHook will be the parent hook.
    void                *ParentHook;
    void                *Context;       ///< User-defined data that will be supplied to the callback.
} HOOK_HEADER, *PHOOK_HEADER;


#include "hook_gpa.h"
#include "hook_ptm.h"
#include "hook_gva.h"
#include "hook_ptwh.h"
#include "hook_pts.h"
#include "hook_object.h"
#include "hook_ptwh.h"


///
/// General hooks-state.
///
typedef struct _HOOK_STATE
{
    HOOK_GPA_STATE          GpaHooks;           ///< GPA hooks state.
    HOOK_GVA_STATE          GvaHooks;           ///< GVA hooks state.
    HOOK_PTM_STATE          PtmHooks;           ///< Page table monitoring (internal) state.
    HOOK_PTS_STATE          PtsHooks;           ///< PTS hooks state (public page-table monitoring).
    HOOK_OBJECT_STATE       Objects;            ///< Object hooks state.
    BOOLEAN                 Dirty;              ///< Set whenever hooks are added or removed.
} HOOK_STATE, *PHOOK_STATE;


extern HOOK_STATE *gHooks;

//
// API
//
INTSTATUS
IntHookCommitAllHooks(
    void
    );

INTSTATUS
IntHookRemoveChain(
    _In_ PHOOK_GPA HookGpa
    );

INTSTATUS
IntHookInit(
    void
    );

INTSTATUS
IntHookUninit(
    void
    );

QWORD
IntHookGetGlaFromGpaHook(
    _In_ HOOK_GPA const *Hook,
    _In_ QWORD Address
    );

#endif // _HOOK_H_
