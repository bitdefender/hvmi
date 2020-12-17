/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   windpi.h
///
/// @brief  Exposes the functions responsible for DPI (Deep Process Inspection) information gathering (used to
/// determine if a process creation should be allowed or not).
///

#ifndef _WINDPI_H_
#define _WINDPI_H_

#include "winguest.h"

typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;

///
/// The maximum number to be checked on DPI heap spray, representing pages from 0x01010000 to 0x0f0f0000.
///
#define HEAP_SPRAY_NR_PAGES 0xF

///
/// Extra info extracted while checking if any DPI heuristic has been violated.
///
typedef struct _DPI_EXTRA_INFO
{
    struct
    {
        QWORD _Reserved;            ///< Reserved for further use.
    } DpiDebugExtraInfo;

    struct
    {
        QWORD CurrentStack;         ///< The current stack of the process at the point of process creation.
        QWORD StackBase;            ///< The known stack base present in TIB at the moment of process creation.
        QWORD StackLimit;           ///< The known stack limit present in TIB at the moment of process creation.
        /// @brief  The address of the trap frame. Used for more information gathering when sending the alert.
        QWORD TrapFrameAddress;
        /// @brief  The current stack of the process in WoW64 mode. Valid only if the process is WoW64.
        QWORD CurrentWow64Stack;
        QWORD Wow64StackBase;       ///< The known stack base in WoW64 mode. Valid only if the process is WoW64.
        QWORD Wow64StackLimit;      ///< The known stack limit in WoW64 mode. Valid only if the process is WoW64.
    } DpiPivotedStackExtraInfo;

    struct
    {
        QWORD StolenFromEprocess;   ///< The EPROCESS address from which the token was stolen.
    } DpiStolenTokenExtraInfo;

    struct
    {
        struct
        {
            DWORD Mapped : 1;           ///< The bit is set if the i-th page could be mapped.
            /// @brief The bit is set if the i-th page was detected as malicious by shemu.
            DWORD Detected : 1;
            /// @brief The number of heap values in the page. Since the max value can be 1024, 11 bits are needed.
            DWORD HeapValCount : 11;
            /// @brief The offset where the detection on the given page was given, if Detection is equal to 1.
            DWORD Offset : 12;
            DWORD Executable : 1;       ///< True if the page is executable in the translation.
            DWORD Reserved : 7;         ///< Reserved for further use.
        } HeapPages[HEAP_SPRAY_NR_PAGES];

        QWORD ShellcodeFlags;           ///< Contains the flags on the first page which was detected through shemu.
    } DpiHeapSprayExtraInfo;

    struct
    {
        QWORD OldEnabled;               ///< The old value from parent's token Privileges.Enabled field.
        /// @brief  The new value from parent's token Privileges.Enabled field, which was deemed malicious.
        QWORD NewEnabled;
        QWORD OldPresent;               ///< The old value from parent's token Privileges.Present field.
        /// @brief  The new value from parent's token Privileges.Present field, which was deemed malicious.
        QWORD NewPresent;
    } DpiTokenPrivsExtraInfo;

    struct
    {
        QWORD StartAddress;             ///< The address on which the parent's thread started execution.
        QWORD ShellcodeFlags;           ///< Contains the flags of the starting page detected through shemu.
    } DpiThreadStartExtraInfo;

    struct
    {
        /// @brief If the parent security descriptor has been stolen, this variable may indicate (in case we find it)
        /// the victim process (where security descriptor has been stolen from) - it can be NULL.
        QWORD SecDescStolenFromEproc;

        QWORD OldPtrValue;              ///< Old value.
        QWORD NewPtrValue;              ///< New value.

        ACL OldSacl;                    ///< The old SACL header.
        ACL OldDacl;                    ///< The old DACL header.

        ACL NewSacl;                    ///< The new SACL header.
        ACL NewDacl;                    ///< The new DACL header.
    } DpiSecDescAclExtraInfo;

} DPI_EXTRA_INFO, *PDPI_EXTRA_INFO;

void
IntWinDpiGatherDpiInfo(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent,
    _In_ QWORD DebugHandle
    );

INTRO_ACTION
IntWinDpiCheckCreation(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent
    );

#endif // _WINDPI_H_
