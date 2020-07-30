/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winummoduleblock.h
///
/// @brief  Exposes the types, constants and functions needed to block Windows module loads (used to block double agent
/// attacks).
///

#ifndef _WINUMMODULEBLOCK_H_
#define _WINUMMODULEBLOCK_H_

#include "winpe.h"

///
/// @brief  DllHandle, Reason and Reserved can be equal to #WINMODBLOCK_INVALID_VALUE when something that is not the
/// entry point of the module (e.g. DllMain) is called.
///
#define WINMODBLOCK_INVALID_VALUE               0xFFFFFFFF


///
/// @brief  Used to provided blocking options
///
typedef enum _WIN_MOD_BLOCK_FLAG
{
    winModBlockFlagUnloadAfterExec = 0x00000001u,   ///< Force the module to unload by returning FALSE.
    winModBlockFlagDoNotUnload = 0x00000002u,       ///< Do not unload the module.
    winModBlockFlagKillOnError = 0x00000004u        ///< Kill the process by injecting a \#PF on CR2 0 if something
                                 ///  fails.
} WIN_MOD_BLOCK_FLAG;


///
/// @brief This callbacks provided detection logic for Windows module loads.
///
/// This callback type can be called for the following reasons:
///     1) At every execution of a suspicious DLL which should be blocked, being mandatory registered through
/// #IntWinModBlockBlockModuleLoad.
///     2) On certain DllMain reasons, as requested by the user, callbacks which are being registered by calls to
/// #IntWinModBlockRegisterCallbackForReason.
///
/// For the case 1) - DllHandle, Reason and Reserved can be equal to WINMODBLOCK_INVALID_VALUE
/// when something that is not the entry point of the module (e.g. DllMain) is called.
/// It is good practice for the callback to verify for DllHandle, Reason and Reserved being equal to
/// WINMODBLOCK_INVALID_VALUE, especially when the callback does something regarding those parameters
/// (e.g. verify reason or do something with the Reserved parameter).
///
typedef INTSTATUS
(*PFUNC_IntWinModBlockCallback)(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ void *BlockObject,
    _In_ QWORD DllHandle,
    _In_ QWORD Reason,
    _In_ QWORD Reserved,
    _In_ QWORD RetAddress,
    _Inout_ INTRO_ACTION *Action
    );

///
/// @brief  This callback type will be called for the suspicious module headers when they are swapped in.
///
/// It is used for getting auxiliary information on the module (e.g. on double agent it is needed for deciding
/// a good address for putting the verifier structures needed for init).
///
typedef INTSTATUS
(*PFUNC_IntWinModBlockHeadersCallback)(
    _Inout_ WIN_PROCESS_MODULE *Module,
    _In_ BYTE *Headers
    );

///
/// @brief  This callback type will be invoked when IntWinModBlockRemoveBlockObject is called for cleanup purposes.
///
/// It is strongly recommended that at least the block object is kept inside the module to be nullified when
/// this is called.
///
typedef INTSTATUS
(*PFUNC_IntWinModBlockCleanup)(
    _Inout_ WIN_PROCESS_MODULE *Module,
    _In_ const void *BlockObject
    );


INTSTATUS
IntWinModBlockBlockModuleLoad(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ WIN_MOD_BLOCK_FLAG Flags,
    _In_ PFUNC_IntWinModBlockCallback Callback,
    _In_opt_ PFUNC_IntWinModBlockHeadersCallback HeadersCallback,
    _In_opt_ PFUNC_IntWinModBlockCleanup CleanupCallback,
    _Inout_ void **BlockObject
    );


INTSTATUS
IntWinModBlockRegisterCallbackForReason(
    _In_ void *BlockObject,
    _In_ DWORD Reason,
    _In_ PFUNC_IntWinModBlockCallback Callback
    );


INTSTATUS
IntWinModBlockRemoveBlockObject(
    _Inout_ void *BlockObject
    );

#endif
