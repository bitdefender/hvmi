/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXMM_H_
#define _LIXMM_H_

#include "lixprocess.h"


///
/// Describes one VMA structure.
///
typedef struct _LIX_VMA
{
    LIST_ENTRY      Link;       ///< Linked list entry.
    QWORD           Gva;        ///< The guest virtual address of the vm_area_struct this structure is based on.

    QWORD           Start;      ///< Start of the memory described by the VMA.
    QWORD           End;        ///< End of the memory described by the VMA.

    /// The Gva of the file this VMA maps to. Can be 0 which means this VMA is not a memory mapped file.
    QWORD           File;

    QWORD           Flags;      ///< Flags for the VMA.

    LIX_TASK_OBJECT *Process;   ///< Process owning the VMA.

    void            *Hook;      ///< The EPT hook placed on the VMA when it is being protected.
} LIX_VMA, *PLIX_VMA;


INTSTATUS
IntLixMmGetInitMm(
    _Out_ QWORD *InitMm
    );

INTSTATUS
IntLixMmFindVmaRange(
    _In_ QWORD Gva,
    _In_ LIX_TASK_OBJECT *Task,
    _Out_ QWORD *VmaStart,
    _Out_ QWORD *VmaEnd
    );

INTSTATUS
IntLixMmFetchVma(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Address,
    _Out_ LIX_VMA *Vma
    );

LIX_VMA *
IntLixMmFindVma(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Vma
    );

LIX_VMA *
IntLixMmFindVmaByRange(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ QWORD Address
    );

INTSTATUS
IntLixMmPopulateVmas(
    _In_ LIX_TASK_OBJECT *Task
    );

void
IntLixMmDestroyVmas(
    _In_ LIX_TASK_OBJECT *Task
    );

void
IntLixMmListVmas(
    _In_ QWORD Mm,
    _In_ LIX_TASK_OBJECT *Process
    );

INTSTATUS
IntLixVmaInsert(
    _In_ void *Detour
    );

INTSTATUS
IntLixVmaChangeProtection(
    _In_ void *Detour
    );

INTSTATUS
IntLixVmaAdjust(
    _In_ void *Detour
    );

INTSTATUS
IntLixVmaExpandDownwards(
    _In_ void *Detour
    );

INTSTATUS
IntLixVmaRemove(
    _In_ void *Detour
    );

#endif // _LIXMM_H_
