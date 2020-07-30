/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINPFN_H_
#define _WINPFN_H_

#include "introtypes.h"

/// @brief  The value used to increment the reference counter of a PFN database entry.
#define WIN_PFN_INC_VALUE   0xbd

/// @brief  The maximum value we allow a PFN reference counter to reach.
#define WIN_PFN_REF_MAX     0xffff

///
/// @brief  A PFN lock.
///
typedef struct _WIN_PFN_LOCK
{
    /// @brief  Entry inside the #gWinPfns list.
    LIST_ENTRY      Link;
    /// @brief  The locked page.
    ///
    /// This could be a guest virtual address, or a guest physical address. If it is a GPA, it is equal to GpaPage.
    QWORD           Page;
    /// @brief  The guest physical page that is locked.
    ///
    /// This is either the page to which Page translates, if Page is a virtual address; or it is equal to Page, if
    /// Page is a physical address.
    QWORD           GpaPage;

    /// @brief  The swap hook used for Page, is Page is a virtual address.
    ///
    /// If Page is a physical address this will be unused.
    void            *SwapHook;

    /// @brief  The reference count.
    ///
    /// This is the reference count used by Introcore, not the one from the guest. It shows how many time Introcore
    /// has locked Page.
    WORD            RefCount;
    /// @brief  True if Page is present.
    ///
    /// If Page is a physical address it will always be True.
    BOOLEAN         Present;
    /// @brief  True if Page is a large page.
    ///
    /// If Page is a virtual address, this means that it is mapped using a page size larger than 4K. If Page is a
    /// physical address we will always consider it a normal, 4K, page and this will be False.
    BOOLEAN         LargePage;
} WIN_PFN_LOCK, *PWIN_PFN_LOCK;

/// @brief      Get the address of a guest _MMPFN structure.
///
/// @param[in]  MmPfn   The guest virtual address of the MMPFN database.
/// @param[in]  Gpa     The guest physical address for which to return the _MMPFN address.
///
/// @returns    The guest virtual address at which the _MMPFN structure for Gpa is found.
#define WIN_PFN_GET_STRUCT_VA(MmPfn, Gpa)                               \
    ((MmPfn) +                                                          \
     ((((gGuest.Guest64 || !gGuest.PaeEnabled)) ?                       \
       WIN_KM_FIELD(Mmpfn, Size) : WIN_KM_FIELD(Mmpfn, PaeSize)) * ((Gpa) >> 12)))

///
/// @brief  Page location value, as defined by the _MMLISTS kernel enum.
///
/// While this is an enum, it is important to note that the Windows kernel uses only 4 bits to store this information.
typedef enum
{
    WinPfnZeroPage = 0,         ///< A page from the ZeroedPageList.
    WinPfnFreePage,             ///< A page from the FreePageList.
    WinPfnStandbyPage,          ///< A page from the StandbyPageList.
    WinPfnModifiedPage,         ///< A page from the ModifiedPageList.
    WinPfnModifiedNowritePage,  ///< A page from the ModifiedNoWritePageList.
    WinPfnBadPage,              ///< A page from the BadPageList.
    WinPfnActivePage,           ///< The page is active and valid, but not part of any list (ActiveAndValid).
    WinPfnTransitionPage,       ///< A temporary state, while waiting for I/O (TransitionPage).
} WIN_PFN_PAGE_LOCATION;

INTSTATUS
IntWinPfnIsMmPfnDatabase(
    _In_ QWORD MmPfnDatabase
    );

INTSTATUS
IntWinPfnLockGva(
    _In_ QWORD Gva,
    _Out_opt_ WIN_PFN_LOCK **PfnLock
    );

INTSTATUS
IntWinPfnLockGpa(
    _In_ QWORD Gpa,
    _Out_opt_ WIN_PFN_LOCK **PfnLock
    );

INTSTATUS
IntWinPfnRemoveLock(
    _Inout_ WIN_PFN_LOCK *PfnLock,
    _In_ BOOLEAN Force
    );

void
IntWinPfnDump(
    void
    );

void
IntWinPfnUnInit(
    void
    );

#endif
