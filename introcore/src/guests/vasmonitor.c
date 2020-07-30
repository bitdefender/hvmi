/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vasmonitor.h"
#include "hook.h"
#include "introcpu.h"

///
/// @file vasmonitor.c
///
/// @brief Contains the virtual address space monitor logic.
///
/// This module contains the virtual address space monitor logic, which involves hooking every page-table belonging
/// to a virtual address space. When any kind of modification takes for a virtual address, the indicated callback
/// will be invoked.
/// NOTE: This module works with an entire virtual address space; therefore, it consumes a lot of memory (it monitors
/// every page-table) and a lot of CPU (since every page-table write will trigger an EPT violation). Please be aware
/// of these when deciding to use it. If you wish to monitor the translation of several virtual addresses, but not
/// an entire address space, use hook_pts instead.
///

///
/// Global VAS state.
///
typedef struct _VAS_STATE
{
    BOOLEAN         Initialized;        ///< Set once the state is initialized.
    LIST_HEAD       MonitoredSpaces;    ///< List of monitored virtual address spaces.
} VAS_STATE, *PVAS_STATE;

static VAS_STATE gVasState = { 0 };


INTSTATUS
IntVasPageTableWriteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

static INTSTATUS
IntVasHookTables(
    _In_ QWORD LinearAddress,
    _In_ QWORD CurrentPage,
    _In_ BYTE PagingMode,
    _In_ BYTE Level,
    _In_ PVAS_ROOT Root,
    _Out_ PVAS_TABLE *Table
    );

static INTSTATUS
IntVasUnHookTables(
    _In_ PVAS_TABLE Table
    );


static INTSTATUS
IntVasDeleteTable(
    _In_ PVAS_TABLE DataAddress,
    _In_ QWORD DataInfo
    )
///
/// @brief Delete the indicated VAS table.
///
/// @param[in]  DataAddress VAS table to be deleted.
/// @param[in]  DataInfo    Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    UNREFERENCED_PARAMETER(DataInfo);

    if (NULL == DataAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL != DataAddress->Entries)
    {
        HpFreeAndNullWithTag(&DataAddress->Entries, IC_TAG_VASE);
    }

    if (NULL != DataAddress->Tables)
    {
        HpFreeAndNullWithTag(&DataAddress->Tables, IC_TAG_VASP);
    }

    HpFreeAndNullWithTag(&DataAddress, IC_TAG_VAST);

    return INT_STATUS_SUCCESS;
}


static QWORD
IntVasGetPageSize(
    _In_ PVAS_TABLE Table
    )
///
/// @brief Computes the size of a page, given a VAS table.
///
/// @param[in]  Table   The VAS table.
///
/// @returns The size of a page referenced by this table.
///
{
    QWORD pageSize;

    if (NULL == Table)
    {
        return 0;
    }

    if (Table->PagingMode == PAGING_4_LEVEL_MODE ||
        Table->PagingMode == PAGING_5_LEVEL_MODE)
    {
        pageSize = (1 == Table->Level) ? PAGE_SIZE_4K : (2 == Table->Level ? PAGE_SIZE_2M : PAGE_SIZE_1G);
    }
    else if (Table->PagingMode == PAGING_PAE_MODE)
    {
        pageSize = (1 == Table->Level) ? PAGE_SIZE_4K : PAGE_SIZE_2M;
    }
    else
    {
        pageSize = (1 == Table->Level) ? PAGE_SIZE_4K : PAGE_SIZE_4M;
    }

    return pageSize;
}


INTSTATUS
IntVasPageTableWriteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle writes inside the monitored page-tables.
///
/// This function handles monitored page-table writes. It has to:
/// 1. Place new hooks on new page-tables, if a new table is being mapped
/// 2. Remove hooks from existing tables, if a table is unmapped
/// 3. Call the translation modification callback, if a leaf entry is modified
///
/// @param[in]  Context     The monitored page-table that is being written to.
/// @param[in]  Hook        GPA hook handle.
/// @param[in]  Address     Written address.
/// @param[in]  Action      Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    PVAS_TABLE pTable;
    PVAS_TABLE_ENTRY pEntry;
    QWORD newValue, oldValue, index, physAddr, gla;
    BOOLEAN oldP, newP, oldPSE, newPSE;
    BYTE sz;

    UNREFERENCED_PARAMETER(Hook);

    if (Context == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    status = INT_STATUS_SUCCESS;
    newValue = oldValue = 0;

    // Actions are always allowed from this handler.
    *Action = introGuestAllowed;

    pTable = (PVAS_TABLE)Context;

    STATS_ENTER(statsVasmon);

    // Get the actual entry that just got written
    switch (pTable->PagingMode)
    {
    case PAGING_5_LEVEL_MODE:
        sz = 8;
        index = (Address & PAGE_OFFSET) >> 3;
        if ((pTable->Level == 5) && (index >= 256))
        {
            // kernel entry written, ignore.
            goto cleanup_and_exit;
        }
        break;
    case PAGING_4_LEVEL_MODE:
        sz = 8;
        index = (Address & PAGE_OFFSET) >> 3;
        if ((pTable->Level == 4) && (index >= 256))
        {
            // kernel entry written, ignore.
            goto cleanup_and_exit;
        }
        break;
    case PAGING_PAE_MODE:
        sz = 8;
        if (pTable->Level == 3)
        {
            index = (Address & 0x1f) >> 3;

            if (index >= 2)
            {
                // kernel entry written, ignore.
                goto cleanup_and_exit;
            }
        }
        else
        {
            index = (Address & PAGE_OFFSET) >> 3;
        }
        break;
    case PAGING_NORMAL_MODE:
        sz = 4;
        index = (Address & PAGE_OFFSET) >> 2;
        if ((pTable->Level == 2) && (index >= 512))
        {
            // kernel entry written, ignore.
            goto cleanup_and_exit;
        }
        break;
    default:
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    // Fetch the entry.
    pEntry = &pTable->Entries[index];

    gla = VAS_COMPUTE_GLA(pTable->LinearAddress, index, pTable->Level, pTable->PagingMode);

    if (introGuestLinux == gGuest.OSType && 0 == gla)
    {
        // Ignore NULL-page mappings on Linux, since they may be mapped inside the kernel
        // and we will have a bad time trying to track them
        goto cleanup_and_exit;
    }

    status = IntHookPtwProcessWrite(&pEntry->WriteState, Address, sz, &oldValue, &newValue);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        *Action = introGuestAllowed;
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }
    else if (!INT_SUCCESS(status))
    {
        QWORD cr3;

        IntCr3Read(gVcpu->Index, &cr3);

        ERROR("[ERROR] IntHookPtwProcessWrite failed at PTE %llx, CR3 %llx (current), CR3 %llx (hooked): 0x%08x\n",
              Address, cr3, pTable->Root->Cr3, status);

        ERROR("[ERROR] Dumping the entire VASMON tables for VA space %llx...\n", pTable->Root->Cr3);

        IntVasDump(pTable->Root->Cr3);

        ERROR("[ERROR] Dumping the entire VASMON tables for VA space %llx DONE!\n", pTable->Root->Cr3);

        IntDbgEnterDebugger();
        goto cleanup_and_exit;
    }
    else if ((INT_STATUS_PARTIAL_WRITE == status) || (INT_STATUS_NOT_NEEDED_HINT == status))
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    pTable->WriteCount++;

    physAddr = newValue & PHYS_PAGE_MASK;

    oldP = (0 != (oldValue & PD_P));
    newP = (0 != (newValue & PD_P));
    oldPSE = (oldP && (0 != (oldValue & PD_PS)));
    newPSE = (newP && (0 != (newValue & PD_PS)));

    if (newP && (0 != (newValue & PT_US)) && (pTable->LinearAddress >= 0xFFFF800000000000))
    {
        LOG("[VASMON] Kernel page 0x%016llx is turning into user page from RIP 0x%016llx: 0x%016llx - 0x%016llx, "
            "CR3 %llx!\n", pTable->LinearAddress, gVcpu->Regs.Rip, oldValue, newValue, pTable->Root->Cr3);
    }

    if (newP && (0 == (newValue & PT_US)) && (pTable->LinearAddress < 0xFFFF800000000000))
    {
        LOG("[VASMON] User page 0x%016llx is turning into kernel page from RIP 0x%016llx: 0x%016llx - 0x%016llx, "
            "CR3 %llx!\n", pTable->LinearAddress, gVcpu->Regs.Rip, oldValue, newValue, pTable->Root->Cr3);
    }

    if (pTable->Level > 1)
    {
        // if we're at level one, than we have a page table. No mappings must be hooked/removed from this level.
        if (oldP && !oldPSE && (!newP || newPSE))
        {
            // Table removed - we will also remove it.
            if (NULL != pTable->Tables[index])
            {
                status = IntVasUnHookTables(pTable->Tables[index]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVasUnHookTable failed: 0x%08x\n", status);
                }
            }

            pTable->Tables[index] = NULL;
        }
        else if (newP && !newPSE && (!oldP || oldPSE))
        {
            // Table mapped - add a hook on it. We also make sure we haven't already hooked it - this may happen
            // on Xen due to duplicate EPT violations.
            if (NULL != pTable->Tables[index])
            {
                status = IntVasUnHookTables(pTable->Tables[index]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVasUnHookTable failed: 0x%08x\n", status);
                }

                pTable->Tables[index] = NULL;
            }

            status = IntVasHookTables(gla,
                                      physAddr,
                                      pTable->PagingMode,
                                      pTable->Level - 1,
                                      pTable->Root,
                                      &pTable->Tables[index]);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", pTable->Root->Cr3, status);
            }
        }
        else if (oldP && newP && !oldPSE && !newPSE &&
                 (CLEAN_PHYS_ADDRESS64(oldValue) != CLEAN_PHYS_ADDRESS64(newValue)))
        {
            // Remapping table.
            if (NULL != pTable->Tables[index])
            {
                status = IntVasUnHookTables(pTable->Tables[index]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVasUnHookTable failed: 0x%08x\n", status);
                }
            }

            pTable->Tables[index] = NULL;

            status = IntVasHookTables(gla,
                                      physAddr,
                                      pTable->PagingMode,
                                      pTable->Level - 1,
                                      pTable->Root,
                                      &pTable->Tables[index]);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", pTable->Root->Cr3, status);
            }
        }

        // On all other cases, a 4K, 2M, 4M or 1G is being mapped, which is uninteresting to us.
    }

    // Invoke the VA space modification callback, if this is a leaf page being modified.
    if (((oldValue & pTable->Root->MonitoredBits) != (newValue & pTable->Root->MonitoredBits)) &&
        ((1 == pTable->Level) || oldPSE || newPSE))
    {
        PFUNC_VaSpaceModificationCallback callback;
        void *context;
        QWORD pageSize;

        callback = pTable->Root->Callback;

        context = pTable->Root->Context;

        pageSize = IntVasGetPageSize(pTable);

        // Invoke the callback.
        if (NULL != callback)
        {
            status = callback(context, gla, oldValue, newValue, pageSize);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] callback failed: 0x%08x\n", status);
            }
        }
    }

cleanup_and_exit:
    STATS_EXIT(statsVasmon);

    return status;
}


static INTSTATUS
IntVasHookTables(
    _In_ QWORD LinearAddress,
    _In_ QWORD CurrentPage,
    _In_ BYTE PagingMode,
    _In_ BYTE Level,
    _In_ PVAS_ROOT Root,
    _Out_ PVAS_TABLE *Table
    )
///
/// @brief Recursively hook all the page-tables starting with the indicated page-table.
///
/// This function will parse the indicated page-table - CurrentPage. It will fetch each entry from it, and it will
/// recursively call the hook function on these entries, until all page-tables have been hooked. On success, it will
/// return a handle to a VAS hook on the current page.
///
/// @param[in]  LinearAddress   The partial linear address that translates through this page-table.
/// @param[in]  CurrentPage     Guest physical address of the current page-table.
/// @param[in]  PagingMode      Paging mode.
/// @param[in]  Level           Current page-table level (5, 4, 3, 2, 1).
/// @param[in]  Root            A root VAS entry.
/// @param[out] Table           A newly hooked page-table.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    QWORD localLinearAddress;
    DWORD i;
    WORD entriesCount;
    VAS_TABLE *pTable;

    if (0 == CurrentPage)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Level)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == Table)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    *Table = NULL;

    pTable = HpAllocWithTag(sizeof(*pTable), IC_TAG_VAST);
    if (NULL == pTable)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Init fields.
    pTable->Level = Level;
    pTable->PagingMode = PagingMode;
    pTable->Root = Root;
    pTable->LinearAddress = LinearAddress;
    pTable->EntriesCount = 0;

    IntPauseVcpus();
    status = IntHookGpaSetHook(CurrentPage,
                               (PAGING_PAE_MODE == PagingMode ? (3 == Level ? 0x20 : 0x1000) : (0x1000)),
                               IG_EPT_HOOK_WRITE,
                               IntVasPageTableWriteCallback,
                               pTable,
                               NULL,
                               HOOK_FLG_PAGING_STRUCTURE,
                               (PHOOK_GPA *)&pTable->WriteHook);
    IntResumeVcpus();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaSetHook failed: 0x%08x\n", status);

        HpFreeAndNullWithTag(&pTable, IC_TAG_VAST);

        return status;
    }


    // Initialize the entries count.
    if (PAGING_4_LEVEL_MODE == PagingMode ||
        PAGING_5_LEVEL_MODE == PagingMode)
    {
        // Long mode paging, 512 entries on each level.
        entriesCount = 512;
    }
    else if (PAGING_PAE_MODE == PagingMode)
    {
        if (3 == Level)
        {
            // PAE mode, root entry, 4 entries.
            entriesCount = 4;
        }
        else
        {
            // PAE mode, intermediary entry, 512 entries.
            entriesCount = 512;
        }
    }
    else
    {
        // Normal mode, 1024 entries on all levels.
        entriesCount = 1024;
    }

    pTable->EntriesCount = entriesCount;

    pTable->Entries = HpAllocWithTag(sizeof(*pTable->Entries) * entriesCount, IC_TAG_VASE);
    if (NULL == pTable->Entries)
    {
        IntHookGpaRemoveHook((HOOK_GPA **)&pTable->WriteHook, 0);

        HpFreeAndNullWithTag(&pTable, IC_TAG_VAST);

        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (Level != 1)
    {
        pTable->Tables = HpAllocWithTag(sizeof(*pTable->Tables) * entriesCount, IC_TAG_VASP);
        if (NULL == pTable->Tables)
        {
            IntHookGpaRemoveHook((HOOK_GPA **)&pTable->WriteHook, 0);

            HpFreeAndNullWithTag(&pTable->Entries, IC_TAG_VASE);

            HpFreeAndNullWithTag(&pTable, IC_TAG_VAST);

            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        pTable->Tables = NULL;
    }

    // Now parse the tables.
    if (PAGING_5_LEVEL_MODE == PagingMode)
    {
        PQWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        for (i = 0; i < (DWORD)((5 == Level) ? 256 : 512); i++)
        {
            localLinearAddress = VAS_COMPUTE_GLA_64(LinearAddress, (QWORD)i, Level);

            // Init current entry
            pTable->Entries[i].WriteState.IntEntry = 0;
            pTable->Entries[i].WriteState.CurEntry = pPage[i];

            if (NULL != pTable->Tables)
            {
                pTable->Tables[i] = NULL;
            }

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    // 4K page.
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    // 2M page
                }
                else if ((3 == Level) && (0 != (pPage[i] & PDP_PS)))
                {
                    // 1G page
                }
                else
                {
                    status = IntVasHookTables(localLinearAddress,
                                              pPage[i] & PHYS_PAGE_MASK,
                                              PagingMode,
                                              Level - 1,
                                              Root,
                                              &pTable->Tables[i]);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", Root->Cr3, status);
                        IntPhysMemUnmap(&pPage);
                        goto cleanup_and_exit;
                    }
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_4_LEVEL_MODE == PagingMode)
    {
        PQWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        for (i = 0; i < (DWORD)((4 == Level) ? 256 : 512); i++)
        {
            localLinearAddress = VAS_COMPUTE_GLA_64(LinearAddress, (QWORD)i, Level);

            // Init current entry
            pTable->Entries[i].WriteState.IntEntry = 0;
            pTable->Entries[i].WriteState.CurEntry = pPage[i];

            if (NULL != pTable->Tables)
            {
                pTable->Tables[i] = NULL;
            }

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    // 4K page.
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    // 2M page
                }
                else if ((3 == Level) && (0 != (pPage[i] & PDP_PS)))
                {
                    // 1G page
                }
                else
                {
                    status = IntVasHookTables(localLinearAddress,
                                              pPage[i] & PHYS_PAGE_MASK,
                                              PagingMode,
                                              Level - 1,
                                              Root,
                                              &pTable->Tables[i]);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", Root->Cr3, status);
                        IntPhysMemUnmap(&pPage);
                        goto cleanup_and_exit;
                    }
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_PAE_MODE == PagingMode)
    {
        PQWORD pPage;

        if (3 != Level)
        {
            status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        }
        else
        {
            status = IntPhysMemMap(CurrentPage, 32, 0, &pPage);
        }
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        for (i = 0; i < (DWORD)((3 == Level) ? 2 : (PAGE_SIZE / 8)); i++)
        {
            localLinearAddress = VAS_COMPUTE_GLA_PAE(LinearAddress, (QWORD)i, Level);

            // Init current entry
            pTable->Entries[i].WriteState.IntEntry = 0;
            pTable->Entries[i].WriteState.CurEntry = pPage[i];

            if (NULL != pTable->Tables)
            {
                pTable->Tables[i] = NULL;
            }

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    // 4K page
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    // 2M page
                }
                else
                {
                    status = IntVasHookTables(localLinearAddress,
                                              pPage[i] & PHYS_PAGE_MASK,
                                              PagingMode,
                                              Level - 1,
                                              Root,
                                              &pTable->Tables[i]);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", Root->Cr3, status);
                        IntPhysMemUnmap(&pPage);
                        goto cleanup_and_exit;
                    }
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_NORMAL_MODE == PagingMode)
    {
        PDWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        for (i = 0; i < (DWORD)(2 == Level ? 512 : 1024); i++)
        {
            localLinearAddress = VAS_COMPUTE_GLA_32(LinearAddress, (QWORD)i, Level);

            // Init current entry
            pTable->Entries[i].WriteState.IntEntry = 0;
            pTable->Entries[i].WriteState.CurEntry = pPage[i];

            if (NULL != pTable->Tables)
            {
                pTable->Tables[i] = NULL;
            }

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    // 4K page
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    // 4M page
                }
                else
                {
                    status = IntVasHookTables(localLinearAddress,
                                              pPage[i] & PHYS_PAGE_MASK,
                                              PagingMode,
                                              Level - 1,
                                              Root,
                                              &pTable->Tables[i]);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntVasHookTables failed in root %llx: 0x%08x\n", Root->Cr3, status);
                        IntPhysMemUnmap(&pPage);
                        goto cleanup_and_exit;
                    }
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

cleanup_and_exit:
    *Table = pTable;

    return status;
}


static INTSTATUS
IntVasUnHookTables(
    _In_ PVAS_TABLE Table
    )
///
/// @brief Every table starting with this one will be deleted.
///
/// @param[in]  Table   The root page-table to be unhooked. All children will also be unhooked.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
//
{
    INTSTATUS status;

    if (NULL == Table)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != Table->WriteHook)
    {
        status = IntHookGpaRemoveHook((HOOK_GPA **)&Table->WriteHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }
    }

    // Only if we have entries.
    if (NULL != Table->Entries)
    {
        for (DWORD i = 0; i < Table->EntriesCount; i++)
        {
            // Recurse and remove child tables.
            if ((NULL != Table->Tables) && (NULL != Table->Tables[i]))
            {
                status = IntVasUnHookTables(Table->Tables[i]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVasUnHookTable failed: 0x%08x\n", status);
                }
            }
            else
            {
                // Remove write/exec hooks by invoking the modification callback.
                PFUNC_VaSpaceModificationCallback callback;
                void *context;
                QWORD pageSize, gla;

                callback = Table->Root->Callback;

                context = Table->Root->Context;

                pageSize = IntVasGetPageSize(Table);

                gla = VAS_COMPUTE_GLA(Table->LinearAddress, i, Table->Level, Table->PagingMode);

                // We need to invoke the callback only for non-zero previous values. Otherwise, the page is
                // not present and we need not do anything.
                status = callback(context, gla, Table->Entries[i].WriteState.CurEntry, 0, pageSize);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] VAS callback failed: 0x%08x\n", status);
                }
            }
        }
    }

    status = IntVasDeleteTable(Table, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVasCleanupCallback failed: 0x%08x\n", status);
    }

    // Done!
    return status;
}


INTSTATUS
IntVasStartMonitorVaSpace(
    _In_ QWORD Cr3,
    _In_ PFUNC_VaSpaceModificationCallback Callback,
    _In_ void *Context,
    _In_ QWORD MonitoredBits,
    _Out_ void **Root
    )
///
/// @brief Start monitoring the indicated virtual address space.
///
/// This function will start to monitor the indicated virtual address space against modifications. Whenever a new page
/// is mapped, unmapped or has its entry modified, the indicated callback will be called.
/// NOTE: This function will NOT call the indicated callback for virtual addresses that are already mapped when enabling
/// the monitor.
///
/// @param[in]  Cr3             The Cr3 of the virtual address space to be monitored.
/// @param[in]  Callback        The callback to be called on translations modifications.
/// @param[in]  Context         Optional context to be passed to the callback on translation modifications.
/// @param[in]  MonitoredBits   The callback will be called if any of these bits are modified.
/// @param[out] Root            A handle to the virtual address space monitor object.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    VAS_ROOT *pVasRoot;

    if (0 == Cr3)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Root)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pVasRoot = HpAllocWithTag(sizeof(*pVasRoot), IC_TAG_VASR);
    if (NULL == pVasRoot)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pVasRoot->Cr3 = Cr3;
    pVasRoot->Callback = Callback;
    pVasRoot->Context = Context;
    pVasRoot->MonitoredBits = MonitoredBits;

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode)
    {
        status = IntVasHookTables(0, Cr3, PAGING_5_LEVEL_MODE, 5, pVasRoot, &pVasRoot->Table);
    }
    else if (PAGING_4_LEVEL_MODE == gGuest.Mm.Mode)
    {
        status = IntVasHookTables(0, Cr3, PAGING_4_LEVEL_MODE, 4, pVasRoot, &pVasRoot->Table);
    }
    else if (PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        status = IntVasHookTables(0, Cr3, PAGING_PAE_MODE, 3, pVasRoot, &pVasRoot->Table);
    }
    else if (PAGING_NORMAL_MODE == gGuest.Mm.Mode)
    {
        WARNING("[WARNING] The paging mode of the system is 32 bit without PAE! Protection is limited (no NX)!\n");

        status = IntVasHookTables(0, Cr3, PAGING_NORMAL_MODE, 2, pVasRoot, &pVasRoot->Table);
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed initiating VA space monitoring for CR3 0x%016llx: 0x%08x\n", Cr3, status);

        // If it managed to hook some tables, than remove the structures.
        if (NULL != pVasRoot->Table)
        {
            IntVasUnHookTables(pVasRoot->Table);
        }

        HpFreeAndNullWithTag(&pVasRoot, IC_TAG_VASR);
    }
    else
    {
        InsertTailList(&gVasState.MonitoredSpaces, &pVasRoot->Link);
    }

    // It will be NULL in case of failure, so it's safe.
    *Root = pVasRoot;

    return status;
}


INTSTATUS
IntVasStopMonitorVaSpace(
    _In_opt_ QWORD Cr3,
    _In_opt_ PVAS_ROOT Root
    )
///
/// @brief Stops monitoring the indicated virtual address space.
///
/// Either Cr3 or Root must be specified. If Root is specified, it will be used instead of Cr3. Otherwise,
/// the actual entry will be searched using the provided CR3. Both arguments cannot be 0 at the same time.
///
/// @param[in]  Cr3     The virtual address space to stop monitoring on.
/// @param[in]  Root    Handle to the virtual address space monitor.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If an indicated monitored space is not found.
///
{
    INTSTATUS status;

    if (NULL == Root)
    {
        LIST_ENTRY *list = gVasState.MonitoredSpaces.Flink;

        while (list != &gVasState.MonitoredSpaces)
        {
            PVAS_ROOT pRoot = CONTAINING_RECORD(list, VAS_ROOT, Link);
            list = list->Flink;

            if (pRoot->Cr3 == Cr3)
            {
                Root = pRoot;
                break;
            }
        }
    }

    if (NULL == Root)
    {
        return INT_STATUS_NOT_FOUND;
    }

    status = IntVasUnHookTables(Root->Table);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVasUnHookTables failed: 0x%08x\n", status);
    }

    RemoveEntryList(&Root->Link);

    HpFreeAndNullWithTag(&Root, IC_TAG_VASR);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVasDumpTables(
    _In_ PVAS_TABLE Table,
    _In_opt_ PVAS_TABLE_ENTRY Parent
    )
///
/// @brief Dump the VAS tables.
///
/// @param[in]  Table   Root table to dump.
/// @param[in]  Parent  Parent entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    DWORD i;
    CHAR *spaces[5] = { "", "        ", "      ", "    ", "  ", };

    LOG("            %s level %d: CUR %llx, INT %llx, mask %x, GPA %llx, GLA %llx\n",
        spaces[Table->Level], Table->Level,
        Parent ? Parent->WriteState.CurEntry : 0,
        Parent ? Parent->WriteState.IntEntry : 0,
        Parent ? Parent->WriteState.WrittenMask : 0,
        ((PHOOK_GPA)Table->WriteHook)->GpaPage,
        Table->LinearAddress);

    if (NULL == Table->Tables)
    {
        return INT_STATUS_SUCCESS;
    }

    for (i = 0; i < Table->EntriesCount; i++)
    {
        if (NULL != Table->Tables[i])
        {
            IntVasDumpTables(Table->Tables[i], &Table->Entries[i]);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntVasDump(
    _In_ QWORD Cr3
    )
///
/// @brief Dump the monitored tables for the indicated Cr3.
///
/// @param[in]  Cr3     The Cr3 to dump the VAS state for.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If the indicated virtual address space is not monitored.
///
{
    INTSTATUS status;
    PVAS_ROOT pRoot;
    LIST_ENTRY *list;

    pRoot = NULL;

    list = gVasState.MonitoredSpaces.Flink;
    while (list != &gVasState.MonitoredSpaces)
    {
        pRoot = CONTAINING_RECORD(list, VAS_ROOT, Link);
        list = list->Flink;

        if (pRoot->Cr3 == Cr3)
        {
            break;
        }

        pRoot = NULL;
    }

    if (NULL == pRoot)
    {
        return INT_STATUS_NOT_FOUND;
    }

    status = IntVasDumpTables(pRoot->Table, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVasUnHookTables failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntVasInit(
    void
    )
///
/// @brief Initialize the VAS monitor state.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    InitializeListHead(&gVasState.MonitoredSpaces);

    gVasState.Initialized = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntVasUnInit(
    void
    )
///
/// @brief Uninit the VAS monitor state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the VAS state has bot been initialized.
///
{
    if (!gVasState.Initialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    gVasState.Initialized = FALSE;

    memzero(&gVasState, sizeof(gVasState));

    return INT_STATUS_SUCCESS;
}
