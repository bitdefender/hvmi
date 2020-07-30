/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixmm.h"
#include "alerts.h"
#include "hook.h"
#include "lixfiles.h"
#include "lixnet.h"
#include "scan_engines.h"
#include "shellcode.h"
#include "lixksym.h"
#include "lixfastread.h"

///
/// @brief The flags set for vDSO mappings.
///
#define LIX_VMA_VDSO_FLAGS      (VM_READ | VM_EXEC | VM_DONTEXPAND | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

///
/// @brief The bit in vma.vm_flags used to mark the VMA protection status.
///
#define LIX_VMA_PROT_MASK       BIT(63)

///
/// @brief Checks if a Vma is a vDSO mapping.
///
#define LIX_VMA_IS_VDSO(Vma)    (((((Vma)->Flags & LIX_VMA_VDSO_FLAGS) == LIX_VMA_VDSO_FLAGS) && (0 == (Vma)->File) && (IntLixVmaGetPageCount(Vma) <= 2)))

///
/// @brief Max VMAs allowed for a process.
///
#define LIX_VMA_MAX_GUEST       (10 * 4096)

///
/// @brief Iterator for the process VMAs.
///
#define for_each_vad(Process, _var_name)        list_for_each((Process)->Vmas, LIX_VMA, _var_name)


static INTSTATUS
IntLixVmaFill(
    _In_ QWORD VmaGva,
    _In_opt_ LIX_TASK_OBJECT *Process,
    _Out_ LIX_VMA *Vma
    );


static inline size_t
IntLixVmaGetPageCount(
    _In_ const LIX_VMA *Vma
    )
///
/// @brief Calculate the number of pages available inside a VMA.
///
/// @param[in] Vma The VMA structure whose page count will be returned.
///
/// @returns The number of pages contained by a VMA.
///
{
#ifdef DEBUG
    if (Vma->Start >= Vma->End)
    {
        ERROR("[ERROR] Invalid VMA [%llx - %llx]\n", Vma->Start, Vma->End);
        IntDumpGva(Vma->Gva, 0x100, gGuest.Mm.SystemCr3);

        return 0;
    }
#endif

    return (Vma->End - Vma->Start) / PAGE_SIZE;
}


INTSTATUS
IntLixMmGetInitMm(
    _Out_ QWORD *InitMm
    )
///
/// @brief Find the address of the "init_mm" variable inside the kernel.
///
/// Searches the linux kernel for the 'init_mm' variable. This variable can be exported in kallsyms but some
/// distros (Debian) disable variable exporting in kallsyms, and we must do it our way then.
///
/// Linux kernel v5.5 defines the init_mm as follows:
///
/// If the "init_mm" address couldn't be resolved via kallsyms then this function will perform a search inside
/// the ".data" section and will apply the following heuristic in order to determine it's address:
///
/// 1. _sdata <= init_mm.pgd < _edata
/// 2. init_mm.mm_list must be a linked list which means the following two conditions must be met:
///     * init_mm.mm_list->next->prev == init_mm
///     * init_mm.mm_list->prev->next == init_mm
/// 3. init_mm.start_code == _etext
/// 4. init_mm.end_code == _etext
/// 5. init_mm.start_data == 0 || init_mm.start_data = _sdata
/// 6. init_mm.end_data == 0 || init_mm.end_data ~ _edata. In some cases the address of "_edata" symbol
/// is just an approximate value.
///
/// @param[out] InitMm Upon successful return will contain the address of the init_mm symbol.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER_1 If the InitMm parameter does not point to a valid memory location.
/// @return INT_STATUS_NOT_FOUND If the symbol address was not found.
///
{
    INTSTATUS status;
    QWORD startGva;

    if (NULL == InitMm)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // It should be there, except on Debian
    startGva = IntKsymFindByName("init_mm", NULL);
    if (startGva)
    {
        *InitMm = startGva;
        return INT_STATUS_SUCCESS;
    }

    for (startGva = gLixGuest->Layout.DataStart & PAGE_MASK;
         startGva < gLixGuest->Layout.DataEnd;
         startGva += PAGE_SIZE)
    {
        BYTE *p;
        BOOLEAN found = FALSE;

        status = IntVirtMemMap(startGva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", startGva, status);
            continue;
        }

        for (QWORD mm = startGva; mm < startGva + PAGE_SIZE; mm += sizeof(QWORD))
        {
            QWORD pgd, next, prev;
            QWORD startCode, endCode, startData, endData;
            DWORD offset = mm & PAGE_OFFSET;

            // 1. init_mm.pgd inside .data
            if (offset + LIX_FIELD(MmStruct, Pgd) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, Pgd), &pgd);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, Pgd), status);
                    continue;
                }
            }
            else
            {
                pgd = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, Pgd));
            }

            if (pgd < gLixGuest->Layout.DataStart || pgd > gLixGuest->Layout.DataEnd)
            {
                continue;
            }

            // 2. init_mm.mmlist it's a list
            // init_mm.mmlist->next->prev = init_mm
            // init_mm.mmlist->prev->next = init_mm
            if (offset + LIX_FIELD(MmStruct, MmList) + 8 >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, MmList), &next);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, MmList), status);
                    continue;
                }

                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, MmList) + 8, &prev);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, MmList) + 8, status);
                    continue;
                }
            }
            else
            {
                next = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, MmList));
                prev = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, MmList) + 8);
            }

            if (!IS_KERNEL_POINTER_LIX(prev) ||
                !IS_KERNEL_POINTER_LIX(next) ||
                prev == 0xffffffffffffffff || next == 0xffffffffffffffff)
            {
                continue;
            }

            if (prev != mm + LIX_FIELD(MmStruct, MmList) + 8)
            {
                QWORD prevNext;

                status = IntKernVirtMemFetchQword(prev, &prevNext);
                if (!INT_SUCCESS(status))
                {
                    continue;
                }

                if (prevNext != mm + LIX_FIELD(MmStruct, MmList))
                {
                    continue;
                }
            }

            if (next != mm + LIX_FIELD(MmStruct, MmList))
            {
                QWORD nextPrev;

                status = IntKernVirtMemFetchQword(next + 8, &nextPrev);
                if (!INT_SUCCESS(status))
                {
                    continue;
                }

                if (nextPrev != mm + LIX_FIELD(MmStruct, MmList))
                {
                    continue;
                }
            }

            // 3. init_mm.start_code = _stext
            if (offset + LIX_FIELD(MmStruct, StartCode) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, StartCode), &startCode);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, StartCode), status);
                    continue;
                }
            }
            else
            {
                startCode = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, StartCode));
            }

            if (startCode != gLixGuest->Layout.CodeStart)
            {
                continue;
            }

            // 4. init_mm.end_code = _etext
            if (offset + LIX_FIELD(MmStruct, EndCode) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, EndCode), &endCode);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, EndCode), status);
                    continue;
                }
            }
            else
            {
                endCode = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, EndCode));
            }

            if (endCode != gLixGuest->Layout.CodeEnd)
            {
                continue;
            }

            // 5. init_mm.start_data = 0 || _etext
            if (offset + LIX_FIELD(MmStruct, StartData) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, StartData), &startData);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, StartData), status);
                    continue;
                }
            }
            else
            {
                startData = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, StartData));
            }

            if (startData != 0 && startData != gLixGuest->Layout.DataStart)
            {
                continue;
            }

            // 6. init_mm.start_data = 0 || _etext
            if (offset + LIX_FIELD(MmStruct, StartData) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, StartData), &startData);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, StartData), status);
                    continue;
                }
            }
            else
            {
                startData = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, StartData));
            }

            if (startData != 0 && startData != gLixGuest->Layout.DataStart)
            {
                continue;
            }

            // 6. init_mm.end_data = 0 || _edata
            if (offset + LIX_FIELD(MmStruct, EndData) >= PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(mm + LIX_FIELD(MmStruct, EndData), &endData);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          mm + LIX_FIELD(MmStruct, EndData), status);
                    continue;
                }
            }
            else
            {
                endData = *(QWORD *)(p + offset + LIX_FIELD(MmStruct, EndData));
            }

            // There are some cases when we can't get the real _edata, and we have to approximate
            if (endData && (endData > gLixGuest->Layout.DataEnd || endData < gLixGuest->Layout.DataStart))

            {
                continue;
            }

            TRACE("[LIXMM] Found init_mm @ 0x%016llx\n", mm);

            *InitMm = mm;

            found = TRUE;

            break;
        }

        IntVirtMemUnmap(&p);

        if (found)
        {
            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixMmFindVmaInLinkedList(
    _In_ QWORD MmGva,
    _In_ QWORD Address,
    _Out_ QWORD *VmaGva,
    _In_ BOOLEAN Backward
    )
///
/// @brief Finds the GVA of the VMA which contains a user memory address by iterating the VMAs linked list of a
/// mm_struct.
///
/// @param[in]  MmGva       The GVA of the mm_struct.
/// @param[in]  Address     The address whose VMA has to be found.
/// @param[out] VmaGva      Upon successful return, this parameter will contain the address of the VMA containing the
///                         Address parameter
/// @param[in]  Backward    This parameter controls if the list should be iterated onward or backwards.
///
/// @returns INT_STATUS_SUCCESS on success.
/// @returns INT_STATUS_NOT_FOUND if the requested VMA was not found.
///
{
    INTSTATUS status;
    DWORD maxIterations = LIX_VMA_MAX_GUEST;
    QWORD currentVma;
    DWORD offset;

    if (Backward)
    {
        offset = LIX_FIELD(Vma, VmPrev);
    }
    else
    {
        offset = LIX_FIELD(Vma, VmNext);
    }

    status = IntKernVirtMemFetchQword(MmGva + LIX_FIELD(MmStruct, Vma), &currentVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%llx: 0x%08x\n", MmGva + LIX_FIELD(MmStruct, Vma), status);
        return status;
    }

    while (IS_KERNEL_POINTER_LIX(currentVma) && maxIterations > 0)
    {
        QWORD nextVma = 0;
        QWORD start, end;

        status = IntLixFsrInitMap(currentVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixFsrInitMap failed for vma 0x%llx: 0x%08x\n", currentVma, status);
            return status;
        }

        status = IntLixFsrRead(currentVma, LIX_FIELD(Vma, VmaEnd), sizeof(end), &end);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read from vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
                  currentVma, LIX_FIELD(Vma, VmaEnd), status);
            goto _done_unmap;
        }

        status = IntLixFsrRead(currentVma, LIX_FIELD(Vma, VmaStart), sizeof(start), &start);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read from vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
                  currentVma, LIX_FIELD(Vma, VmaStart), status);

            goto _done_unmap;
        }

        if (IN_RANGE(Address, start, end))
        {
            *VmaGva = currentVma;

            status = INT_STATUS_SUCCESS;

            goto _done_unmap;
        }

        status = IntLixFsrRead(currentVma, offset, sizeof(nextVma), &nextVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read next vma from 0x%llx at offset 0x%x. Status: 0x%08x\n",
                  currentVma, offset, status);

            goto _done_unmap;
        }

        IntLixFsrUninitMap();

        currentVma = nextVma;
        maxIterations--;
    }

    return INT_STATUS_NOT_FOUND;

_done_unmap:

    IntLixFsrUninitMap();

    return status;
}


INTSTATUS
IntLixMmFindVmaInRbTree(
    _In_ QWORD MmGva,
    _In_ QWORD Address,
    _Out_ QWORD *VmaGva
    )
///
/// @brief Finds the GVA of the VMA which contains a user memory address traversing the VMA rb tree of the mm_struct.
///
/// This function will attempt to find the Address inside the red black tree within 64 iterations. This limit should
/// be high enough since it allows a maximum of 2^64 -1 objects.
///
/// The red black tree implementation allows the lock-free lookup. It guarantees that a found item is correct. However,
/// it does not guarantee that if an item is not found it doesn't exist. Check
/// https://elixir.bootlin.com/linux/v5.5/source/lib/rbtree.c for an in-depth explanation.
///
/// It is highly recommended to perform a  #IntLixMmFindVmaInLinkedList call when this function fails in order to
/// make sure that the Address indeed does not exist.
///
/// @param[in]  MmGva   The GVA of the mm_struct.
/// @param[in]  Address The address whose VMA has to be found.
/// @param[out] VmaGva  Upon successful return, this parameter will contain the address of the VMA containing the
///                     Address parameter.
///
/// @returns INT_STATUS_SUCCESS on success.
/// @returns INT_STATUS_NOT_FOUND if the requested VMA was not found.
///
{
    INTSTATUS status;
    QWORD rbGva, vmaGva;
    LIX_RB_NODE node;
    QWORD vmaStart, vmaEnd;
    QWORD maxIterations = 64;

    vmaStart = vmaEnd = rbGva = 0;

    status = IntKernVirtMemFetchQword(MmGva + LIX_FIELD(MmStruct, RbNode), &rbGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read rb_node for mm 0x%llx. Status: 0x%08x\n", MmGva, status);
        return status;
    }

    while (rbGva)
    {
        if (!maxIterations--)
        {
            ERROR("[ERROR] Max iterations limit reached!\n");
            return INT_STATUS_NOT_FOUND;
        }

        vmaGva = rbGva - LIX_FIELD(Vma, RbNode);

        status = IntLixFsrInitMap(vmaGva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to map vma 0x%llx. Status: 0x%08x\n", vmaGva, status);
            return status;
        }

        status = IntLixFsrRead(vmaGva, LIX_FIELD(Vma, VmaEnd), sizeof(vmaEnd), &vmaEnd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read from vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
                  vmaGva, LIX_FIELD(Vma, VmaEnd), status);

            goto _done_unmap;
        }

        status = IntLixFsrRead(vmaGva, LIX_FIELD(Vma, RbNode), sizeof(node), &node);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read from vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
                  vmaGva, LIX_FIELD(Vma, RbNode), status);

            goto _done_unmap;
        }

        if (vmaEnd > Address)
        {
            status = IntLixFsrRead(vmaGva, LIX_FIELD(Vma, VmaStart), sizeof(vmaStart), &vmaStart);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed to read from vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
                      vmaGva, LIX_FIELD(Vma, VmaStart), status);
                goto _done_unmap;
            }

            if (vmaStart <= Address)
            {
                *VmaGva = vmaGva;

                status = INT_STATUS_SUCCESS;

                goto _done_unmap;
            }

            rbGva = node.Left;
        }
        else
        {
            rbGva = node.Right;
        }

        IntLixFsrUninitMap();
    }

    return INT_STATUS_NOT_FOUND;

_done_unmap:

    IntLixFsrUninitMap();

    return status;
}


INTSTATUS
IntLixMmFetchVma(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Address,
    _Out_ LIX_VMA *Vma
    )
///
/// @brief Retrieve information about a VMA structure containing a user mode address.
///
/// @param[in]  Task    The process on whose mm space the address should be searched.
/// @param[in]  Address The searched address.
/// @param[out] Vma     Upon successful return will contain information about the requested VMA.
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_INVALID_PARAMETER_* if any parameter is invalid.
/// @return INT_STATUS_NOT_FOUND if the requested VMA was not found.
///
{
    INTSTATUS status;
    QWORD vmaGva;

    if (Task == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Vma)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    status = IntLixMmFindVmaInRbTree(Task->MmGva, Address, &vmaGva);
    if (INT_SUCCESS(status))
    {
        goto _fill;
    }

    WARNING("[WARNING] Failed to find addr 0x%llx in rbtree for task %s (%d, 0x%llx), mm 0x%llx. Status: 0x%08x\n",
            Address, Task->Comm, Task->Pid, Task->Gva, Task->MmGva, status);

    status = IntLixMmFindVmaInLinkedList(Task->MmGva, Address, &vmaGva, FALSE);
    if (INT_SUCCESS(status))
    {
        goto _fill;
    }

    status = IntLixMmFindVmaInLinkedList(Task->MmGva, Address, &vmaGva, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to find addr in linked list\n");
        return INT_STATUS_NOT_FOUND;
    }

_fill:

    return IntLixVmaFill(vmaGva, Task, Vma);
}


INTSTATUS
IntLixMmFindVmaRange(
    _In_ QWORD Gva,
    _In_ LIX_TASK_OBJECT *Task,
    _Out_ QWORD *VmaStart,
    _Out_ QWORD *VmaEnd
    )
///
/// @brief Finds the VMA limits that contain an address.
///
/// @param[in]  Gva      The address that will be searched.
/// @param[in]  Task     The process the process on whose address space the search will be performed.
/// @param[out] VmaStart Upon successful return will contain the lower limit of the VMA.
/// @param[out] VmaEnd   Upon successful return will contain the upper limit of the VMA.
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_INVALID_PARAMETER_* if any parameter is invalid.
///
{
    LIX_VMA vad;
    INTSTATUS status;

    if (IS_KERNEL_POINTER_LIX(Gva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Task)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == VmaStart)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == VmaEnd)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *VmaStart = *VmaEnd = 0;

    status = IntLixMmFetchVma(Task, Gva, &vad);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmFetchVma failed for task %s(%d, 0x%llx) gva 0x%llx, mm 0x%llx. Status: 0x%08x\n",
              Task->Comm, Task->Pid, Task->Gva, Gva, Task->MmGva, status);
        return status;
    }

    *VmaStart = vad.Start;
    *VmaEnd = vad.End;

    return INT_STATUS_SUCCESS;
}


LIX_VMA *
IntLixMmFindVmaByRange(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ QWORD Address
    )
///
/// @brief Finds if a memory address inside a process is being protected and returns the corresponding LIX_VMA structure.
///
/// @param[in] Process
/// @param[in] Address
///
/// @returns NULL if the address is not being protected.
/// @returns The LIX_VMA structure containing the address.
///
{
    for_each_vad(Process, pVma)
    {
        if (Address >= pVma->Start && Address < pVma->End)
        {
            return pVma;
        }
    }

    return NULL;
}


static LIX_VMA *
IntLixVmaFindByGva(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ QWORD Vma
    )
///
/// @brief Finds if a VMA is being protected and returns the corresponding LIX_VMA structure.
///
/// @param[in] Process
/// @param[in] Vma
///
/// @returns NULL if the VMA is not being protected.
/// @returns The LIX_VMA structure corresponding to the requested VMA.
///
{
    for_each_vad(Process, pVma)
    {
        if (Vma == pVma->Gva)
        {
            return pVma;
        }
    }

    return NULL;
}


static INTSTATUS
IntLixVmaFill(
    _In_ QWORD VmaGva,
    _In_opt_ LIX_TASK_OBJECT *Process,
    _Out_ LIX_VMA *Vma
    )
///
/// @brief Retrieves in-guest information about a VMA and stores them in a LIX_VMA structure.
///
/// @param[in]  VmaGva  The GVA of the vma based on which the LIX_VMA will be created.
/// @param[in]  Process The process owning the VMA.
/// @param[out] Vma     Upon successful return the structure will be filled with details regarding the VMA.
///
/// @return INT_STATUS_SUCCESS on success.
///
{
    INTSTATUS status;

    memzero(Vma, sizeof(*Vma));

    status = IntLixFsrInitMap(VmaGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFsrInitMap failed for vma %llx: 0x%08x\n", VmaGva, status);
        return status;
    }

    Vma->Gva = VmaGva;

    status = IntLixFsrRead(VmaGva, LIX_FIELD(Vma, VmaStart), sizeof(Vma->Start), &Vma->Start);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading vm_area_struct->vm_start: %08x\n", status);
        goto _done;
    }

    status = IntLixFsrRead(VmaGva, LIX_FIELD(Vma, VmaEnd), sizeof(Vma->End), &Vma->End);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading vm_area_struct->vm_end: %08x\n", status);
        goto _done;
    }

    status = IntLixFsrRead(VmaGva, LIX_FIELD(Vma, Flags), sizeof(Vma->Flags), &Vma->Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading vm_area_struct->vm_flags: %08x\n", status);
        goto _done;
    }

    status = IntLixFsrRead(VmaGva, LIX_FIELD(Vma, File), sizeof(Vma->File), &Vma->File);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading vm_area_struct->vm_file: %08x\n", status);
        goto _done;
    }

    Vma->Process = Process;

    status = INT_STATUS_SUCCESS;

_done:
    IntLixFsrUninitMap();

    return status;
}


INTSTATUS
IntLixVmaCreate(
    _In_ QWORD VmaGva,
    _In_ LIX_TASK_OBJECT *Process,
    _Out_ LIX_VMA **Vma
    )
///
/// @brief Creates a LIX_VMA object.
///
/// @param[in]  VmaGva  The GVA of the vma based on which the LIX_VMA will be created.
/// @param[in]  Process The process owning the VMA.
/// @param[out] Vma     Upon successful return will contain the pointer to the newly created LIX_VMA object.
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_INSUFFICIENT_RESOURCES if there was not enough memory to allocate the object.
///
{
    INTSTATUS status;
    LIX_VMA *pVma;

    *Vma = NULL;

    pVma = HpAllocWithTag(sizeof(*pVma), IC_TAG_VMA);
    if (NULL == pVma)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntLixVmaFill(VmaGva, Process, pVma);
    if (!INT_SUCCESS(status))
    {
        goto _free_vad;
    }

    InsertTailList(&Process->Vmas, &pVma->Link);

    *Vma = pVma;

    status = INT_STATUS_SUCCESS;

_free_vad:
    if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&pVma, IC_TAG_VMA);
    }

    return status;
}


LIX_VMA *
IntLixMmFindVma(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Vma
    )
///
/// @brief Finds a protected VMA inside a process VMA list.
///
/// @param[in] Task The process in whose list the Vma should be found.
/// @param[in] Vma  The Gva of a VMA object.
///
/// @return NULL if the VMA was not found.
/// @return The LIX_VMA object associated with the Vma parameter.
///
{
    for_each_vad(Task, pVma)
    {
        if (pVma->Gva == Vma)
        {
            return pVma;
        }
    }

    return NULL;
}


static INTSTATUS
IntVmaMarkProtection(
    _In_ LIX_VMA *Vma,
    _In_ BOOLEAN Protected
    )
///
/// @brief Marks the VMA as either protected or unprotected.
///
/// Based on the Protected parameter value, the vma's flags inside the guest will be patched to
/// reflect whether it is protected or not. This mechanism is used in order to increase the performance
/// by ignoring any changes on VMAs that are not protected by Introcore.
///
/// @param[in] Vma       The VMA that should be marked.
/// @param[in] Protected TRUE if the VMA should be marked as protected, FALSE otherwise.
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_NOT_NEEDED_HINT if no action had to be taken.
///
{
    INTSTATUS status;
    QWORD newFlags = 0, oldFlags = 0;

    status = IntKernVirtMemFetchQword(Vma->Gva + LIX_FIELD(Vma, Flags), &oldFlags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword IntVirtMemFetchQwordUnmapV GVA 0x%016llx: %08x\n",
              Vma->Gva + LIX_FIELD(Vma, Flags), status);
        return status;
    }

    if (Protected)
    {
        newFlags = oldFlags | LIX_VMA_PROT_MASK;
    }
    else
    {
        newFlags = oldFlags & (~LIX_VMA_PROT_MASK);
    }

    if (oldFlags == newFlags)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // NOTE: IntVirtMemSafeWrite should be used instead, but it will induce significant performance penalty.
    status = IntKernVirtMemPatchQword(Vma->Gva + LIX_FIELD(Vma, Flags), newFlags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemPatchQword failed for GVA 0x%016llx: %08x\n",
              Vma->Gva + LIX_FIELD(Vma, Flags), status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVmaRemoveProtection(
    _In_ LIX_VMA *Vma,
    _In_ BOOLEAN Mark
    )
///
/// @brief Removes the protection for a VMA.
///
/// @param[in] Vma The VMA whose protection will be removed.
/// @param[in] Mark TRUE if the caller wants to also mark the VMA as unprotected.
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_NOT_NEEDED_HINT if the Vma is not being protected.
///
{
    INTSTATUS status = INT_STATUS_NOT_NEEDED_HINT;

    if (Vma->Hook)
    {
        status = IntHookObjectRemoveRegion((HOOK_REGION_DESCRIPTOR **)&Vma->Hook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectRemoveRegion failed: %08x\n", status);
        }
    }

    if (Mark)
    {
        status = IntVmaMarkProtection(Vma, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVmaMarkProtection failed: %08x\n", status);
            return status;
        }
    }

    return status;
}


static void
IntLixVmaDestroy(
    _Inout_ LIX_VMA *Vma
    )
///
/// @brief Destroys a LIX_VMA object.
///
/// Removes the EPT hooks established for the given VMA and mark it as unprotected. This function
/// will also destroy the LIX_VMA object removing it from the internal list and freeing the
/// allocated memory.
///
/// @param[in] Vma The VMA which will be destroyed.
///
{
    IntLixVmaRemoveProtection(Vma, TRUE);

    RemoveEntryList(&Vma->Link);
    HpFreeAndNullWithTag(&Vma, IC_TAG_VMA);
}


void
IntLixMmDestroyVmas(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Remove protection for the VMAs belonging to a process.
///
/// @param[in] Task The process whose VMAs will be unprotected.
///
{
    for_each_vad(Task, pVma)
    {
        IntLixVmaDestroy(pVma);
    }

    InitializeListHead(&Task->Vmas);
}


static INTSTATUS
IntLixVmaHandlePageExecution(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Linux user mode page execution handler.
///
/// This function will review the analyze the violation and will decide if the execution is malicious or not based on
/// the following heuristic:
///
///   1. Check if the ESP points inside the (known) actual (current) stack
///   2. Check if the address is on the current stack
///   3. Check if the page is still writable
///   4. Check if the page was created with write rights, but no execute rights
///   5. Check last branch (might not be doable on Xen)
///   6. Code analysis (smallest priority)
///
/// The previous checks may have three outcomes:
///  * The attempt was not malicious, in which case the EPT hook is removed in order to increase performance (but the
/// VMA will be still marked as protected!) and the instruction will be retried.
///  * The attempt was malicious. In this case this action may be excepted and the action taken on previous point will
/// be taken here also.
///
/// If the attempt was malicious and it was not excepted, and the PROC_OPT_KILL_ON_EXPLOIT option is available,
/// then a UD exception will be injected in order to crash the victim. Even if the injected UD will trigger a segmentation fault
/// which can be caught by an exception handler, the  #IntLixCrashHandle function will make sure that the signal
/// delivered is SIGKILL instead of SIGSEGV.
///
/// @param[in]  Context The context provided to #IntHookGpaSetHook.
/// @param[in]  Hook    The GPA_HOOK object.
/// @param[in]  Address The GPA access that trigger the violation.
/// @param[out] Action  Will contain the action that should be taken regarding the violation.
///
/// @return INT_STATUS_SUCCESS on success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_VMA *pVma, *pStackVma;
    LIX_TASK_OBJECT *pTask;
    IG_ARCH_REGS *regs;
    INSTRUX *instrux;
    BOOLEAN bRspOut, bIsStack;
    QWORD rip;
    QWORD scflags;
    BOOLEAN detected, feedback, excepted;
    INTRO_ACTION action = introGuestNotAllowed;
    INTRO_ACTION_REASON reason = introReasonUnknown;
    INFO_UD_PENDING *entryPendingUD = NULL;
    EXCEPTION_UM_ORIGINATOR originator = {0};
    EXCEPTION_VICTIM_ZONE victim = {0};

    UNREFERENCED_PARAMETER(Hook);

    *Action = introGuestAllowed;
    detected = excepted = feedback = FALSE;

    regs = &gVcpu->Regs;
    instrux = &gVcpu->Instruction;
    rip = gVcpu->Gla;

    pVma = (LIX_VMA *)Context;
    pTask = pVma->Process;

    entryPendingUD = IntUDGetEntry(regs->Cr3, regs->Rip, pTask->Gva);
    if (NULL != entryPendingUD)
    {
        goto _retry_inject_ud;
    }

    bIsStack = (pVma->Flags & VM_GROWSDOWN) != 0;

    pStackVma = IntLixMmFindVmaByRange(pTask, regs->Rsp);
    if (pStackVma)
    {
        bIsStack = ((rip >= pStackVma->Start) && (rip < pStackVma->End));
    }

    bRspOut = FALSE;

    status = IntShcIsSuspiciousCode(rip, Address, IG_CS_TYPE_INVALID, regs, &scflags);
    if (!INT_SUCCESS(status))
    {
        scflags = 0;
    }

    if (bRspOut || bIsStack)
    {
        // Pivoted stack or executions on the stack trigger detection directly.
        detected = TRUE;
    }
    else if (0 != scflags)
    {
        detected = TRUE;

        // Shellcode flags (as set by the shellcode emulator) may be overridden via CAMI. A flag marked for feedback
        // will cause the alert to be logged & sent, but no actual detection will appear. Note that we force feedback
        // for shellcode flags if and only if all the reported flags are marked as feedback. If there is a single
        // shellcode flag set that is not feedback, a normal detection will be generated.
        if ((scflags & gGuest.ShemuOptions.Feedback) == scflags)
        {
            feedback = TRUE;
        }
    }

    // We did not find malicious activity, send context to the scan engine if we have the options set.
    if (!detected && !!(gGuest.CoreOptions.Current & INTRO_OPT_NOTIFY_ENGINES))
    {
        INTRO_EXEC_INFO executionInfo = { 0 };
        INTSTATUS status2;

        // We could fail the entire EPT callback because of this.
        status2 = IntLixTaskGetUserStack(pTask, NULL, &executionInfo.StackBase, &executionInfo.StackLimit);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] Failed to get user mode stack for process %s (%d, 0x%llx). Status: 0x%08x\n",
                  pTask->Comm, pTask->Pid, pTask->Gva, status);
        }

        executionInfo.Rsp = regs->Rsp;
        executionInfo.Length = instrux->Length;

        status2 = IntLixEngExecSendNotification(pTask, regs, &executionInfo);
        if (!INT_SUCCESS(status2))
        {
            WARNING("[WARNING] IntLixEngExecSendNotification failed: 0x%08x\n", status2);
        }
    }

    if (detected)
    {
        status = IntExceptUserGetExecOriginator(pTask, &originator);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
            goto _send_notification;
        }

        status = IntExceptGetVictimEpt(pTask,
                                       gVcpu->Gpa,
                                       gVcpu->Gla,
                                       introObjectTypeUmGenericNxZone,
                                       ZONE_EXECUTE,
                                       &victim);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
            goto _send_notification;
        }

        IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventEptViolation);

        if (action == introGuestAllowed)
        {
            excepted = TRUE;
        }
        else if (action == introGuestNotAllowed && feedback)
        {
            action = introGuestAllowed;
            reason = introReasonAllowedFeedback;
        }
    }

_send_notification:
    if (detected && (!excepted)) // 0x7f6e0000
    {
        PEVENT_EPT_VIOLATION pEptViol = NULL;
        char text[ND_MIN_BUF_SIZE] = { 0 };

        status = NdToText(instrux, rip, ND_MIN_BUF_SIZE, text);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] NdToText failed: 0x%08x\n", status);
            snprintf(text, sizeof(text), "<invalid>");
        }

        LOG("[VMANX] [CPU %d] EXPLOIT detected! Execution attempted at 0x%016llx! Instruction: %s\n",
            gVcpu->Index, rip, text);

        LOG("[VMANX] Current address: %llx, current stack: %llx, known stack: %llx/%llx\n",
            rip, regs->Rsp, pStackVma ? pStackVma->End : 0, pStackVma ? pStackVma->Start : 0);

        IntDumpCodeAndRegs(regs->Rip, Address, regs);

        pEptViol = &gAlert.Ept;

        memset(pEptViol, 0, sizeof(*pEptViol));

        pEptViol->Header.Action = action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idExploitClientExec;

        pEptViol->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_EXPLOIT, pTask, reason, 0);

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);
        IntAlertFillLixProcess(pTask, &pEptViol->Header.CurrentProcess);

        IntAlertFillVersionInfo(&pEptViol->Header);
        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        IntAlertFillExecContext(regs->Cr3, &pEptViol->ExecContext);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = IntLixNetSendTaskConnections(pTask);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixNetSendTaskConnections failed: %08x\n", status);
        }

        // Override the status returned by IntNotifyIntroEvent.
        status = INT_STATUS_SUCCESS;

        // Block by default.
        *Action = introGuestNotAllowed;
    }

    IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_EXPLOIT, pTask, Action);

    // Remove the exec hook if we allow the action.
    if (introGuestAllowed == *Action)
    {
        // Remove the hook on this region, only if we didn't block anything. If we did, we will maintain the hook in
        // order to block further execution attempts. We also remove the hook if we're in BETA mode - otherwise,
        // there will be lots & lots of alerts, that may end up hanging the process.
        status = IntLixVmaRemoveProtection(pVma, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaRemoveProtection failed for vad [%llx - %llx]: %08x\n",
                  pVma->Start, pVma->End, status);
        }

        // Since we remove the exec-hook, we can simply retry the execution of the instruction. This way, we don't
        // have to emulate or single step the instruction.
        *Action = introGuestRetry;
    }

_retry_inject_ud:
    // Terminate the process, if needed.
    if ((INT_SUCCESS(status) && (introGuestNotAllowed == *Action) &&
         (0 != (pTask->Protection.Mask & PROC_OPT_KILL_ON_EXPLOIT))) ||
        NULL != entryPendingUD)
    {
        INTSTATUS status2;

        pTask->MustKill = TRUE;

        // If we already injected the same entry, there's no need for another injection, most probably causing an error
        if (entryPendingUD != NULL && gVcpu->CurrentUD == entryPendingUD)
        {
            goto _skip_inject;
        }

        status2 = IntInjectExceptionInGuest(VECTOR_UD, 0, NO_ERRORCODE, gVcpu->Index);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntInjectExceptionInGuest failed, process will not be killed: %08x\n", status2);
        }
        else
        {
            if (NULL == entryPendingUD)
            {
                // If not already pending, add to the list of pending UDs and store the allocated address in entryPendingUD
                status = IntUDAddToPendingList(regs->Cr3, regs->Rip, pTask->Gva, &entryPendingUD);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVadAddToPendingUDList failed: %08x\n", status);
                }
            }

            // Set gVcpu->CurrentUD pointer to the allocated address for the tuple
            gVcpu->CurrentUD = entryPendingUD;
        }
_skip_inject:
        *Action = introGuestRetry;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVmaProtect(
    _In_ LIX_VMA *Vma
    )
///
/// @brief Activates protection for a VMA.
///
/// This function will establish the GVA hooks for the given vma and will mark it as protected.
///
/// @param[in] Vma The vma to protect
///
/// @return INT_STATUS_SUCCESS on success.
/// @return INT_STATUS_NOT_NEEDED_HINT if the vma represents a memory mapped file or if the vma is not executable.
/// @return INT_STATUS_INVALID_OBJECT_TYPE if the vma range is not greater than 0.
///
{
    INTSTATUS status;

    if (0 == (Vma->End - Vma->Start))
    {
        WARNING("[WARNING] Vma %llx [%llx - %llx] can't be protected!\n", Vma->Gva, Vma->Start, Vma->End);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if ((Vma->File && IntLixVmaGetPageCount(Vma) >= 2) || (0 == (Vma->Flags & VM_EXEC)))
    {
        // No need to log anything. This is a valid use case where we really need re-monitor some changes.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (Vma->Hook)
    {
        LOG("[ERROR] [VMA] Special case when protecting an already protected vad [%llx - %llx]\n",
            Vma->Start, Vma->End);

        status = IntLixVmaRemoveProtection(Vma, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaRemoveProtection failed for vad [%llx - %llx]: %08x\n",
                  Vma->Start, Vma->End, status);
        }
    }

    if (__unlikely((Vma->End - Vma->Start) > ONE_GIGABYTE))
    {
        WARNING("[WARNING] Big vad  [%llx - %llx] (%ld pages) in process '%s' (%d)\n",
                Vma->Start, Vma->End, IntLixVmaGetPageCount(Vma), Vma->Process->ProcName, Vma->Process->Pid);
        goto _mark_protection;
    }

    status = IntHookObjectHookRegion(Vma->Process->HookObject,
                                     Vma->Process->Cr3,
                                     Vma->Start,
                                     Vma->End - Vma->Start,
                                     IG_EPT_HOOK_EXECUTE,
                                     IntLixVmaHandlePageExecution,
                                     Vma,
                                     0,
                                     (HOOK_REGION_DESCRIPTOR **)&Vma->Hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed for [%llx - %llx]: %08x\n",
              Vma->Start, Vma->End, status);
        return status;
    }

_mark_protection:
    status = IntVmaMarkProtection(Vma, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVmaMarkProtection failed: %08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixMmPopulateVmasInternal(
    _In_ LIX_TASK_OBJECT *Process,
    _In_ BOOLEAN Backward
    )
///
/// @brief Iterate the VMA linked list of a process in the given direction and protect the executable ones.
///
/// This function will iterate in the given direction the VMAs linked list of a process and the ones that are
/// marked as executable but are not file mappings will be cached internally and protected. The vDSO VMA is
/// ignored since it is protected globally.
///
/// @param[in] Process  The process whose VMA list this function will iterate.
/// @param[in] Backward If the list should be iterated backwards.
///
/// @return INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD currentVma;
    DWORD offset;
    DWORD maxIterations;

    status = IntKernVirtMemFetchQword(Process->MmGva + LIX_FIELD(MmStruct, Vma), &currentVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", Process->MmGva, status);
        return status;
    }

    if (Backward)
    {
        QWORD prevVma = 0;

        status = IntKernVirtMemFetchQword(currentVma + LIX_FIELD(Vma, VmPrev), &prevVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", Process->MmGva, status);
            return status;
        }

        currentVma = prevVma;
    }

    maxIterations = LIX_VMA_MAX_GUEST;
    if (Backward)
    {
        offset = LIX_FIELD(Vma, VmPrev);
    }
    else
    {
        offset = LIX_FIELD(Vma, VmNext);
    }

    while (IS_KERNEL_POINTER_LIX(currentVma) && maxIterations > 0)
    {
        QWORD nextVma = 0;
        LIX_VMA *pVma = NULL;
        LIX_VMA vad;
        BOOLEAN shouldProtect;

        status = IntLixVmaFill(currentVma, Process, &vad);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaFill failed for vma %llx: %08x\n", currentVma, status);
            return status;
        }

        shouldProtect = (0 == vad.File && (vad.Flags & VM_EXEC));

        if (LIX_VMA_IS_VDSO(&vad))
        {
            // This is the VDSO, don't protect it for now (we will protect it globally)
            shouldProtect = FALSE;
        }

        if (shouldProtect)
        {
            status = IntLixVmaCreate(currentVma, Process, &pVma);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixVmaCreate failed for vma %llx: %08x\n", currentVma, status);
                return status;
            }

            status = IntLixVmaProtect(pVma);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixVmaProtect failed for vad [%llx - %llx] flags %08llx, 0x%016llx: %08x\n",
                      pVma->Start, pVma->End, pVma->Flags, pVma->Gva, status);

                IntLixVmaDestroy(pVma);
            }
        }

        status = IntKernVirtMemFetchQword(currentVma + offset, &nextVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for vma %llx: %08x\n", currentVma, status);
            return status;
        }

        currentVma = nextVma;
        --maxIterations;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixMmPopulateVmas(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Populate the Introcore VMAs linked list by iterating the one inside the guest.
///
/// This function will iterate the in-guest VMA list and attempt to protect the ones which are
/// marked as executable.
///
/// @param[in] Task The process whose VMA list should be populated.
///
/// @return INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (NULL == Task)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntLixMmPopulateVmasInternal(Task, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmPopulateVmasInternal failed for forward parsing: %08x\n", status);
        goto _free_and_exit;
    }

    status = IntLixMmPopulateVmasInternal(Task, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmPopulateVmasInternal failed for backward parsing: %08x\n", status);
        goto _free_and_exit;
    }

    return INT_STATUS_SUCCESS;

_free_and_exit:
    IntLixMmDestroyVmas(Task);

    return status;
}


static void
IntLixMmListVmasInternal(
    _In_ QWORD Mm,
    _In_ LIX_TASK_OBJECT *Process,
    _In_ BOOLEAN Backward
    )
///
/// @brief Logs all VMAs from a mm_struct.
///
/// Iterates the VMA linked list of the given mm_struct and lists their attributes, such as
/// VmaStart, VmaEnd, VmaFlags and page count.
///
/// @param[in] Mm       The guest virtual address of the mm_struct whose VMAs will be listed.
/// @param[in] Process  The process owning the mm_struct.
/// @param[in] Backward If set to TRUE, the VMA linked list will be iterated backwards.
///
{
    INTSTATUS status;
    QWORD currentVma;
    DWORD offset;
    DWORD maxIterations;

    status = IntKernVirtMemFetchQword(Mm + LIX_FIELD(MmStruct, Vma), &currentVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", Mm + LIX_FIELD(MmStruct, Vma), status);
        return;
    }

    if (Backward)
    {
        QWORD prevVma = 0;

        status = IntKernVirtMemFetchQword(currentVma + LIX_FIELD(Vma, VmPrev), &prevVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", Mm, status);
            return;
        }

        currentVma = prevVma;
    }

    maxIterations = LIX_VMA_MAX_GUEST;

    if (Backward)
    {
        offset = LIX_FIELD(Vma, VmPrev);
    }
    else
    {
        offset = LIX_FIELD(Vma, VmNext);
    }

    while (IS_KERNEL_POINTER_LIX(currentVma) && maxIterations > 0)
    {
        QWORD nextVma = 0;
        LIX_VMA vma;
        char *fileName = NULL;

        status = IntLixVmaFill(currentVma, NULL, &vma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaFill failed for vma 0x%016llx: %08x\n", currentVma, status);
            return;
        }

        status = IntLixGetFileName(vma.File, &fileName, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            fileName = NULL;
        }

        LOG("  [%016llx -> %016llx] : %08llx @ 0x%016llx Hooked=%d (%c%c%c) => %06ld pages '%s'\n",
            vma.Start, vma.End, vma.Flags, vma.Gva, vma.Hook ? 1 : 0,
            (vma.Flags & VM_EXEC) ? 'X' : '-',
            (vma.Flags & VM_WRITE) ? 'W' : '-',
            (vma.Flags & VM_READ) ? 'R' : '-',
            IntLixVmaGetPageCount(&vma),
            fileName);

        DWORD presentPages = 0;
        for (size_t i = 0; i < IntLixVmaGetPageCount(&vma); i++)
        {
            QWORD physAddress;

            status = IntTranslateVirtualAddress(vma.Start + (i * PAGE_SIZE), Process->Cr3, &physAddress);
            if (!INT_SUCCESS(status))
            {
                continue;
            }

            presentPages++;
        }

        LOG("-----> %d/%ld present pages\n", presentPages, IntLixVmaGetPageCount(&vma));

        if (fileName)
        {
            HpFreeAndNullWithTag(&fileName, IC_TAG_NAME);
        }

        status = IntKernVirtMemFetchQword(currentVma + offset, &nextVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for vma %llx: %08x\n", currentVma, status);
            return;
        }

        currentVma = nextVma;
        --maxIterations;
    }

}


void
IntLixMmListVmas(
    _In_ QWORD Mm,
    _In_ LIX_TASK_OBJECT *Process)
{
///
/// @brief Logs all VMAs from a mm_struct.
///
/// @param[in]    Mm      The mm_struct GVA.
/// @param[in]    Process Pointer to a LIX_TASK_OBJECT structure.
///
    if (!Mm)
    {
        return;
    }

    IntLixMmListVmasInternal(Mm, Process, FALSE);
    IntLixMmListVmasInternal(Mm, Process, TRUE);
}


INTSTATUS
IntLixVmaInsert(
    _In_ void *Detour
    )
///
/// @brief Detour handler for "__vma_link_rb" function.
///
/// This function is called when an executable VMA is being created. If the newly created VMA is already protected (by a
/// previous vma_adjust call) then it will be ignored.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the process is not recognized, it is not protected or the vma is not protected.
///
{
    INTSTATUS status;
    QWORD vma = gVcpu->Regs.R8;
    QWORD mm = gVcpu->Regs.R9;
    LIX_VMA *pVma;

    UNREFERENCED_PARAMETER(Detour);

    LIX_TASK_OBJECT *pTask = IntLixTaskFindByMm(mm);
    if (__unlikely((NULL == pTask) || !(pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVma = IntLixMmFindVma(pTask, vma);
    if (pVma)
    {
        // It was already created by vma_adjust, no need to do anything
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntLixVmaCreate(vma, pTask, &pVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaCreate failed: %08x\n", status);
        return status;
    }

    if (LIX_VMA_IS_VDSO(pVma))
    {
        IntLixVmaDestroy(pVma);

        return INT_STATUS_SUCCESS;
    }

    status = IntLixVmaProtect(pVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaProtect failed: 0x%08x\n", status);
        IntLixVmaDestroy(pVma);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixVmaChangeProtection(
    _In_ void *Detour
    )
///
/// @brief Detour handler for "change_protection" function.
///
/// This function is called whenever a VMA belonging to a protected memory space is making a transition from executable
/// to non-executable and vice-versa. If the VMA if being marked as executable than this function will establish the
/// protection, otherwise the protection will be removed and it will be marked as unprotected.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the process is not recognized, it is not protected or the vma is not protected.
///
{
    INTSTATUS status;
    QWORD vma = gVcpu->Regs.R8;
    QWORD mm = gVcpu->Regs.R9;
    QWORD newFlags = 0;
    LIX_TASK_OBJECT *pTask;
    LIX_VMA *pVma;

    UNREFERENCED_PARAMETER(Detour);

    pTask = IntLixTaskFindByMm(mm);
    if (__unlikely((NULL == pTask) || !(pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVma = IntLixMmFindVma(pTask, vma);

    status = IntKernVirtMemFetchQword(vma + LIX_FIELD(Vma, Flags), &newFlags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
        return status;
    }

    newFlags &= ~LIX_VMA_PROT_MASK;

    if (newFlags & VM_EXEC)
    {
        BOOLEAN newlyCreated = FALSE;

        if (NULL == pVma)
        {
            newlyCreated = TRUE;

            status = IntLixVmaCreate(vma, pTask, &pVma);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixVmaCreate failed for vma %llx: %08x\n", vma, status);
                return status;
            }
        }

        pVma->Flags = newFlags & (~LIX_VMA_PROT_MASK);

        if (newlyCreated || (newFlags != pVma->Flags))
        {
            status = IntLixVmaProtect(pVma);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixVmaProtect failed for vad [%llx - %llx] flags %08llx, 0x%016llx: %08x\n",
                      pVma->Start, pVma->End, pVma->Flags, pVma->Gva, status);

                IntLixVmaDestroy(pVma);

                return status;
            }
        }
    }
    else if (pVma)
    {
        IntLixVmaDestroy(pVma);
        pVma = NULL;
    }

    if (pVma)
    {
        pVma->Flags = newFlags;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVmaIntervalChanged(
    _In_ LIX_VMA *AdjustedVma,
    _In_opt_ QWORD InsertVma
    )
///
/// @brief Simply re-apply the protection for the given vma.
///
/// Will shrink or expand the given VMA. Will also create & insert a new vad located at InsertVma if needed.
/// This is because the InsertVma, most probably, contain a sub-part of the AdjustedVma, and this way we can
/// simply copy the hooks to the new vad, instead of deleting & re-hooking them on the next exit (it's very slow
/// that way).
///
/// @param[in] AdjustedVma The Vma whose interval changed.
/// @param[in] InsertVma   The GVA of a newly created vma.
///
/// @return INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // We must remove the old protection first
    status = IntLixVmaRemoveProtection(AdjustedVma, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaRemoveProtection failed for vad [%llx - %llx]: %08x\n",
              AdjustedVma->Start, AdjustedVma->End, status);
        return status;
    }

    status = IntLixVmaProtect(AdjustedVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaProtect failed: 0x%08x\n", status);
        return status;
    }

    if (InsertVma)
    {
        LIX_VMA *pInsVma;

        status = IntLixVmaCreate(InsertVma, AdjustedVma->Process, &pInsVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntLixVmaProtect(pInsVma);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaProtect failed: 0x%08x\n", status);

            IntLixVmaDestroy(pInsVma);

            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixVmaExpandDownwards(
    _In_ void *Detour
    )
///
/// @brief Detour handler for "expand_downwards" function.
///
/// This function updates the protection for VMAs which are able to expand downwards (usually this is
/// the case for stack VMAs). It checks if the lower limit has changed and updates the protected memory range.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the process is not recognized, it is not protected or the vma is not protected.
///
{
    INTSTATUS status;
    QWORD mm;
    QWORD vma = gVcpu->Regs.R8;
    QWORD address = gVcpu->Regs.R9;
    LIX_TASK_OBJECT *pTask;
    LIX_VMA *pVma;

    UNREFERENCED_PARAMETER(Detour);

    status = IntKernVirtMemFetchQword(vma + LIX_FIELD(Vma, Mm), &mm);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for vma %llx: %08x\n", vma, status);
        return status;
    }

    pTask = IntLixTaskFindByMm(mm);
    if (__unlikely((NULL == pTask) || !(pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVma = IntLixMmFindVma(pTask, vma);
    if (NULL == pVma)
    {
        return INT_STATUS_SUCCESS;
    }

    if (address < pVma->Start)
    {
        QWORD oldStart = pVma->Start;

        pVma->Start = address;

        status = IntLixVmaIntervalChanged(pVma, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaIntervalChanged failed for vad [%llx/%llx - %llx/%llx] flags %08llx, 0x%016llx: %08x\n",
                  pVma->Start, oldStart, pVma->End, pVma->End, pVma->Flags, pVma->Gva, status);

            IntLixVmaDestroy(pVma);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVmaAdjustInternal(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Vma
    )
///
/// @brief Checks if the VMA limits have changed and updates the protected memory range.
///
/// @param[in] Task Process the Vma belongs to.
/// @param[in] Vma  The GVA of the vma structure to be processed.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the parameters are invalid or the Vma is not being protected.
///
{
    INTSTATUS status;
    LIX_VMA *pVma;
    QWORD oldStart, oldEnd;
    QWORD addr = 0;

    if (NULL == Task || 0 == Vma)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVma = IntLixMmFindVma(Task, Vma);
    if (NULL == pVma)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    oldStart = pVma->Start;
    oldEnd = pVma->End;
    addr = pVma->Gva;

    status = IntLixFsrInitMap(addr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFsrInitMap failed for Vma 0x%llx: 0x%08x\n", pVma->Gva, status);
        return status;
    }

    status = IntLixFsrRead(addr, LIX_FIELD(Vma, VmaStart), sizeof(QWORD), &pVma->Start);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read from Vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
              pVma->Gva, LIX_FIELD(Vma, VmaStart), status);

        goto _done_unmap;
    }

    status = IntLixFsrRead(addr, LIX_FIELD(Vma, VmaEnd), sizeof(QWORD), &pVma->End);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read from Vma 0x%llx at offset 0x%x. Status: 0x%08x\n",
              pVma->Gva, LIX_FIELD(Vma, VmaEnd), status);

        goto _done_unmap;
    }

    if (oldStart != pVma->Start || oldEnd != pVma->End)
    {
        status = IntLixVmaIntervalChanged(pVma, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVmaIntervalChanged failed for vad [%llx/%llx - %llx/%llx] flags %08llx, 0x%016llx: %08x\n",
                  pVma->Start, oldStart, pVma->End, oldEnd, pVma->Flags, pVma->Gva, status);

            IntLixVmaDestroy(pVma);
        }
    }

    status = INT_STATUS_SUCCESS;

_done_unmap:

    IntLixFsrUninitMap();

    return status;
}


INTSTATUS
IntLixVmaAdjust(
    _In_ void *Detour
    )
///
/// @brief Detour handler for in-guest functions adjusting VMA ranges.
///
/// This function checks the result of the "vma_adjust" call and adjust the protection for the
/// affected VMAs.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the process is either not recognized or it's not being protected.
///
{
    INTSTATUS status;

    QWORD vma = gVcpu->Regs.R8;
    QWORD mm = gVcpu->Regs.R9;

    QWORD next = gVcpu->Regs.R10;
    QWORD prev = gVcpu->Regs.R11;

    LIX_TASK_OBJECT *pTask;

    UNREFERENCED_PARAMETER(Detour);

    pTask = IntLixTaskFindByMm(mm);
    if (__unlikely((NULL == pTask) || !(pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntLixVmaAdjustInternal(pTask, vma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaAdjustInternal failed for vma 0x%llx (mm gva: 0x%llx) from task %s (%d 0x%llx). Status: 0x%08x\n",
              vma, pTask->MmGva, pTask->Comm, pTask->Pid, pTask->Gva, status);
    }

    status = IntLixVmaAdjustInternal(pTask, next);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaAdjustInternal failed for vma 0x%llx (mm gva: 0x%llx) from task %s (%d 0x%llx). Status: 0x%08x\n",
              next, pTask->MmGva, pTask->Comm, pTask->Pid, pTask->Gva, status);
    }

    status = IntLixVmaAdjustInternal(pTask, prev);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVmaAdjustInternal failed for vma 0x%llx (mm gva: 0x%llx) from task %s (%d 0x%llx). Status: 0x%08x\n",
              prev, pTask->MmGva, pTask->Comm, pTask->Pid, pTask->Gva, status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixVmaRemove(
    _In_ void *Detour
    )
///
/// @brief Detour handler for functions that unmap memory for processes.
///
/// This functions removes the protection from a vma as it's being unmapped from the process memory space. Usually, the
/// kernel function that will trigger this event is "(__)vma_rb_erase". Because the support for RHEL 6 required lots of
/// hacks and workarounds, other functions may trigger this. However, every detour must provide this function the
/// Gva of the removed VMA in R8 register and the Gva  mm struct owning the VMA in R9 register.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the process is not recognized, it is not protected or the vma is not protected.
///
{
    QWORD vma = gVcpu->Regs.R8;
    QWORD mm = gVcpu->Regs.R9;

    LIX_TASK_OBJECT *pTask;
    LIX_VMA *pVma;

    UNREFERENCED_PARAMETER(Detour);

    pTask = IntLixTaskFindByMm(mm);
    if (__unlikely((NULL == pTask) || !(pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVma = IntLixMmFindVma(pTask, vma);
    if (NULL == pVma)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntLixVmaDestroy(pVma);

    return INT_STATUS_SUCCESS;
}
