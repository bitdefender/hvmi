/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINUMMODULE_H_
#define _WINUMMODULE_H_

#include "winumcache.h"
#include "winvad.h"

#define NAMEHASH_NTDLL          0xbe9d4ec5
#define NAMEHASH_KERNEL32       0x72f47653
#define NAMEHASH_KERNELBASE     0x2945f399
#define NAMEHASH_USER32         0xb8d0fd42

#define NAMEHASH_WOW64          0xb29d7275
#define NAMEHASH_WOW64WIN       0xb3ad9cbb
#define NAMEHASH_WOW64CPU       0x824c82be

#define NAMEHASH_WS2_32         0x3d20b35c
#define NAMEHASH_WININET        0x7350cbf8

#define NAMEHASH_VERIFIER       0x3608e61f
#define NAMEHASH_APISETSCHEMA   0x6b8a8a45


///
/// Describes a process module.
///
typedef struct _WIN_PROCESS_MODULE
{
    LIST_ENTRY          Link;                   ///< List entry element.

    QWORD               VirtualBase;            ///< Guest virtual address of the loaded module.
    DWORD               Size;                   ///< Virtual size of the module.

    union
    {
        DWORD           Flags;                  ///< Raw flags.
        struct
        {
            DWORD       ShouldProtHooks: 1;     ///< TRUE if the module should be protected against hooks.
            DWORD       ShouldProtUnpack: 1;    ///< TRUE if the module should be protected against unpack.
            DWORD       UnpackAlertSent: 1;     ///< TRUE if unpack alerts have been sent.
            DWORD       Is64BitModule: 1;       ///< TRUE if the module is 64 bit.
            DWORD       IsProtected: 1;         ///< TRUE if the module is actually hooked.
            DWORD       IsMainModule: 1;        ///< TRUE if this is the main module
            DWORD       IsSystemModule : 1;     ///< TRUE if this is a system module (loaded from system32 or syswow64).
            DWORD       LoadEventSent: 1;       ///< TRUE if the load event has been sent.
            DWORD       UnloadEventSent: 1;     ///< TRUE if the unload event has been sent.
            DWORD       IsSuspicious: 1;        ///< TRUE if the module is suspicious.
            DWORD       SuspChecked: 1;         ///< TRUE if the module has been checked against DoubleAgent.
            /// @brief  TRUE if the module was found by statically enumerating process modules.
            DWORD       StaticScan: 1;
            DWORD       ShouldGetCache: 1;      ///< TRUE if the module headers should be cached.
            DWORD       DoubleAgentAlertSent: 1;///< TRUE if a DoubleAgent alert has been sent on this module.
        };
    };

    PWIN_PROCESS_SUBSYSTEM  Subsystem;          ///< Module subsystem.

    WINUM_PATH              *Path;              ///< Module path.
    WINUM_MODULE_CACHE      *Cache;             ///< Module headers cache.

    DWORD                   IATEntries;         ///< Number of IAT entries.
    PBYTE                   IATBitmap;          ///< A bitmap indicating which IAT entries have been initialized.

    void                    *HookObject;        ///< Module hook object.
    void                    *HeadersSwapHandle; ///< Swap handle for the headers.
    void                    *ExportsSwapHandle; ///< Swap handle for the exports.

    void                    *ModBlockObject;    ///< Module load block handle.

    /// @brief  The address between sections on which we put the needed verifier structure on double agent.
    QWORD                   SlackSpaceForVerifier;
    /// @brief  The address received by DllMain where the pointer to verifier structure should be put.
    QWORD                   AddressOfVerifierData;
    /// @brief  A flag which is set in order to verify if the first execution (for init phase)
    /// is done on double agent case.
    BOOLEAN                 FirstDoubleAgentExecDone;
    /// @brief  Swap handle for the slack space page where we put verifier structures.
    void                    *SlackSpaceSwapHandle;

    /// @brief Needed for verifying if the process main module is from the Native subsystem or not
    /// (e.g. doesn't load kernel32.dll).
    void                    *MainModHeadersSwapHandle;

    const VAD               *Vad;               ///< The VAD which describes this module.

} WIN_PROCESS_MODULE, *PWIN_PROCESS_MODULE;


///
/// Describes a protected DLL.
///
typedef struct _PROTECTED_DLL_INFO
{
    WCHAR   *Name;      ///< Name.
    DWORD   NameHash;   ///< Name hash.
} PROTECTED_DLL_INFO, * PPROTECTED_DLL_INFO;


#define MODULE_MATCH(m, p)      ((((m)->Path->NameHash == (p)->NameHash)) && \
                                (0 == memcmp((m)->Path->Name, (p)->Name, (m)->Path->NameSize)))


//
// API
//
INTSTATUS
IntWinModHandleLoadFromVad(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ const VAD *Vad
    );

INTSTATUS
IntWinModHandleUnloadFromVad(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PVAD Vad
    );

INTSTATUS
IntWinModHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntWinModPolyHandler(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PINSTRUX Instrux,
    _In_ void *Context
    );

INTSTATUS
IntWinModUnHookModule(
    _In_ PWIN_PROCESS_MODULE Module
    );

INTSTATUS
IntWinModRemoveModule(
    _In_ PWIN_PROCESS_MODULE Module
    );

void
IntWinModulesChangeProtectionFlags(
    _In_ PWIN_PROCESS_SUBSYSTEM Subsystem
    );

PWIN_PROCESS_MODULE
IntWinUmModFindByAddress(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Gva
    );

INTSTATUS
IntWinModHandlePreInjection(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    );

INTSTATUS
IntWinProcSendAllDllEventsForProcess(
    _In_ PWIN_PROCESS_OBJECT Process
    );

#endif // _WINUMMODULE_H_
