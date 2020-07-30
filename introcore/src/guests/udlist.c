/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "udlist.h"
#include "guests.h"

///
/// @file udlist.c
///
/// @brief Maintains a list of pending UD injections for each (Cr3, Rip, Thread) tuple.
///
/// This module manages a list of pending UD injections. When Introcore blocks an exploit inside a process, there
/// is an option of killing the attacked process, as there is no reliable way execution can continue. Killing the
/// process is done by injecting an undefined opcode exception (UD) inside the process, which will cause it to die.
/// However, when Introcore requests an exception injection inside the guest, there is no guarantee that the
/// exception would actually get injected (it may be overwritten by the HV, some other event with a higher
/// priority may get injected, etc.). Therefore, when we see an exploit for the first time and decide to kill
/// the process, we will allocate a UD injection entry. If the injection fails, the exploit would try to execute
/// again, but since we already have a pending UD entry, we won't generate another alert, and we will re-inject
/// this UD again. The UD entry will be freed as soon as the exception is injected (thanks to the
/// #IntHandleEventInjection callback inside callbacks.c).
///

/// The list of pending UD injections. Once a UD gets injected, its entry will be removed from this list.
LIST_HEAD gListPendingUD = LIST_HEAD_INIT(gListPendingUD);


INTSTATUS
IntUDAddToPendingList(
    _In_ const QWORD Cr3,
    _In_ const QWORD Rip,
    _In_ const QWORD Thread,
    _Out_ INFO_UD_PENDING **CurrentPendingUD
    )
///
/// @brief Add a new UD to the list of pending injections.
///
/// This function will create a pending UD entry for the provided CR3, RIP, and thread ID. This will allow us later
/// to check if we have already injected a UD for a given context, so we can avoid injecting it multiple times.
///
/// @param[in]  Cr3                 The Cr3.
/// @param[in]  Rip                 The RIP.
/// @param[in]  Thread              The thread ID (software thread!).
/// @param[out] CurrentPendingUD    Will contain, upon successful return, the newly allocated pending UD entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INFO_UD_PENDING *infoUD;

    if (0 == Cr3)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Rip)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Thread)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == CurrentPendingUD)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    infoUD = HpAllocWithTag(sizeof(*infoUD), IC_TAG_UDCX);
    if (NULL == infoUD)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    infoUD->Cr3 = Cr3;
    infoUD->Rip = Rip;
    infoUD->Thread = Thread;

    // Add the entry to the list of pending UDs
    InsertTailList(&gListPendingUD, &infoUD->Link);

    // After #UD is injected (IntHandleEventInjection), we will remove the entry from the list and for that,
    // we need to keep this info
    *CurrentPendingUD = infoUD;

    return INT_STATUS_SUCCESS;
}


void
IntUDRemoveEntry(
    _Inout_ INFO_UD_PENDING **InfoUD
    )
///
/// @brief Remove a pending UD entry.
///
/// Remove the given entry from the list of UD entries and free it.
///
/// @param[in, out] InfoUD  The pending UD.
///
{
    if (NULL != InfoUD && NULL != *InfoUD)
    {
        RemoveEntryList(&(*InfoUD)->Link);
        HpFreeAndNullWithTag(InfoUD, IC_TAG_UDCX);
    }
}


void
IntUDRemoveAllEntriesForCr3(
    _In_ const QWORD Cr3
    )
///
/// @brief Remove all pending UD entries for a given virtual address space.
///
/// NOTE: Use this function when a process is being terminated.
///
/// @param[in]  Cr3     The target CR3.
///
{
    list_for_each(gListPendingUD, INFO_UD_PENDING, pInfoUD)
    {
        if (Cr3 == pInfoUD->Cr3)
        {
            WARNING("[WARNING] There are still pending UDs in the list when process terminates (will remove them) "
                    "CR3: 0x%016llx RIP: 0x%016llx THREAD: 0x%016llx\n",
                    pInfoUD->Cr3, pInfoUD->Rip, pInfoUD->Thread);

            for (DWORD index = 0; index < gGuest.CpuCount; index++)
            {
                if (pInfoUD == gGuest.VcpuArray[index].CurrentUD)
                {
                    gGuest.VcpuArray[index].CurrentUD = NULL;
                }
            }

            IntUDRemoveEntry(&pInfoUD);
        }
    }
}


INFO_UD_PENDING *
IntUDGetEntry(
    _In_ const QWORD Cr3,
    _In_ const QWORD Rip,
    _In_ const QWORD Thread
    )
///
/// @brief Get a UD entry for the provided Cr3, Rip and Thread ID.
///
/// @param[in]  Cr3     The Cr3.
/// @param[in]  Rip     The Rip.
/// @param[in]  Thread  The thread ID (software thread!).
///
/// @returns The pending UD entry, if one is found, or NULL if none is found.
///
{
    list_for_each(gListPendingUD, INFO_UD_PENDING, pInfoUD)
    {
        if (Cr3 == pInfoUD->Cr3 && Rip == pInfoUD->Rip && Thread == pInfoUD->Thread)
        {
            TRACE("[INFO] Already an UD pending for CR3: 0x%016llx RIP: 0x%016llx THREAD: 0x%016llx\n",
                  pInfoUD->Cr3, pInfoUD->Rip, pInfoUD->Thread);

            return pInfoUD;
        }
    }

    return NULL;
}
