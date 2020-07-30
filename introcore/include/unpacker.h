/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UNPACKER_H_
#define _UNPACKER_H_

#include "introtypes.h"
#include "bddisasm.h"


///
/// @brief Called when a page is considered to be "unpacked".
///
/// This callback is called when Introcore suspects that a monitored page has been unpacked. Put simply, the unpack
/// algorithm simply watches for pages that have been executed after being modified.
///
/// @param[in]  Cr3             Virtual address space.
/// @param[in]  VirtualAddress  The virtual address of the unpacked paged.
/// @param[in]  Instrux         The decode instruction that has just been fetched for execution.
/// @param[in]  Context         Optional context, as passed to the monitor function.
///
typedef INTSTATUS
(*PFUNC_PageUnpackedCallback)(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PINSTRUX Instrux,
    _In_ void *Context
    );


///
/// @brief Called when a page is written.
///
/// This callback is called when a monitored page is written. The callback is used to validate the write - to determine
/// if the write is legitimate or not. A legitimate write could be, for example, a write inside the IAT, made by the
/// loader. Legitimate writes are not considered by the algorithm - for example, if only legitimate writes take place
/// inside the page, and the page is executed, the unpack callback will not be triggered.
///
/// @param[in]  Cr3             Virtual address space.
/// @param[in]  VirtualAddress  The virtual address of the unpacked paged.
/// @param[in]  Context         Optional context, as passed to the monitor function.
///
/// @returns True if the write is legitimate, or false otherwise.
///
typedef BOOLEAN
(*PFUNC_PageIsWriteValid)(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ void *Context
    );


//
// API
//
INTSTATUS
IntUnpWatchPage(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PFUNC_PageUnpackedCallback UnpackCallback,
    _In_ PFUNC_PageIsWriteValid WriteCheckCallback,
    _In_opt_ void *CallbackContext
    );

INTSTATUS
IntUnpUnWatchPage(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    );

INTSTATUS
IntUnpUnWatchVaSpacePages(
    _In_ QWORD Cr3
    );

INTSTATUS
IntUnpRemovePages(
    void
    );

void
IntUnpUninit(
    void
    );

#endif // _UNPACKER_H_
