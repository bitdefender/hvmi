/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXMODULE_H_
#define _LIXMODULE_H_

#include "introtypes.h"


#define LIX_MODULE_NAME_LEN             56  ///< The maximum length of the Linux module name.
#define LIX_ACTIVE_PATCH_SIZE           27  ///< The maximum size of the active-patch data.

///
/// @brief  The layout of the core/init sections.
///
typedef struct _LIX_MODULE_LAYOUT
{
    QWORD       Base;               ///< The base GVA of the section.
    DWORD       Size;               ///< The total size of the section.
    DWORD       TextSize;           ///< The size of the .text (code usually).
    DWORD       RoSize;             ///< The size of the .rodata (read-only).
} LIX_MODULE_LAYOUT, *PLIX_MODULE_LAYOUT;


///
/// @brief The internal structure of the Linux-driver
///
typedef struct _LIX_KERNEL_MODULE
{
    void                *InitSwapHook;              ///< The hook on the init section.

    DWORD               SymbolsCount;               ///< The number of symbols (num_syms).
    DWORD               GplSymbolsCount;            ///< The number of GPL-exported symbols (num_gpl_syms).

    QWORD               KernelSymbols;              ///< The GVA of the exported symbols (syms).
    QWORD               GplSymbols;                 ///< The GVA of the exported gpl symbols (gpl_syms).

    LIX_MODULE_LAYOUT   InitLayout;                 ///< The layout of the init section.
    LIX_MODULE_LAYOUT   CoreLayout;                 ///< The layout of the core section.

    /// @brief  The hook object used to protect this driver against read. NULL if the driver is not protected.
    void                *HookObjectRead;

    BOOLEAN             Initialized;                ///< This means that the init section is discarded.
} LIX_KERNEL_MODULE, *PLIX_KERNEL_MODULE;


typedef struct _KERNEL_DRIVER KERNEL_DRIVER, *PKERNEL_DRIVER;
typedef struct _LIX_ACTIVE_PATCH LIX_ACTIVE_PATCH, *PLIX_ACTIVE_PATCH;

///
/// @brief The internal structure of the Linux active-patch.
///
typedef struct _LIX_KERNEL_PATCH
{
    LIST_ENTRY  Link;                           ///< List entry element.

    QWORD       Gva;                            ///< The start of the region which follows to be patched.
    WORD        Length;                         ///< The patch length.
    WORD        PatchedLength;                  ///< The size of the already patched area.

    BYTE        Patch[LIX_ACTIVE_PATCH_SIZE];   ///< The content of the active-patch.

    BOOLEAN     CodeValid;
} LIX_KERNEL_PATCH, *PLIX_KERNEL_PATCH;


INTSTATUS
IntLixDrvFindList(
    _Out_ QWORD *Drivers
    );

INTSTATUS
IntLixDrvRemoveEntry(
    _In_ KERNEL_DRIVER *Driver
    );

void
IntLixDrvGetSecName(
    _In_ KERNEL_DRIVER *Driver,
    _In_ QWORD Gva,
    _Out_writes_(8) CHAR *SectionName
    );

INTSTATUS
IntLixDrvIsLegitimateTextPoke(
    _In_ void *Hook,
    _In_ QWORD Address,
    _In_ LIX_ACTIVE_PATCH *ActivePatch,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntLixDrvHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntLixDrvIterateList(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    );

INTSTATUS
IntLixDrvCreateFromAddress(
    _In_ QWORD DriverGva,
    _In_ QWORD StaticDetected
    );

INTSTATUS
IntLixDrvRemoveFromAddress(
    _In_ QWORD DriverGva
    );

INTSTATUS
IntLixDrvCreateKernel(
    void
    );

void
IntLixDrvUpdateProtection(
    void
    );

#endif // _LIXMODULE_H_
