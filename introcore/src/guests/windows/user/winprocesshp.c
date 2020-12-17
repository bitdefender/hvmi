/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winprocesshp.h"
#include "guests.h"
#include "vasmonitor.h"
#include "winummodule.h"

/// @brief  The list of all the processes inside the guest.
LIST_HEAD gWinProcesses = LIST_HEAD_INIT(gWinProcesses);
/// @brief  Tree of all the processes inside the guest, using the kernel CR3 as the key.
RBTREE gWinProcTreeCr3 = RB_TREE_INIT(gWinProcTreeCr3, IntWinProcRbTreeNodeFree, IntWinProcRbTreeNodeCompareCr3);
/// @brief  Tree of all the processes inside the guest, using the user-mode CR3 as the key/
RBTREE gWinProcTreeUserCr3 = RB_TREE_INIT(gWinProcTreeUserCr3, IntWinProcRbTreeNodeFree,
                                          IntWinProcRbTreeNodeCompareUserCr3);
/// @brief  Tree of all the processes inside the guest, using the _EPROCESS address as the key.
RBTREE gWinProcTreeEprocess = RB_TREE_INIT(gWinProcTreeEprocess, IntWinProcRbTreeNodeFree,
                                           IntWinProcRbTreeNodeCompareEproc);

void
IntWinProcLstUnsafeReInit(void)
///
/// @brief  Reinitializes the Windows process lists and trees, without doing any cleanup.
///
/// This resets the #gWinProcesses lists, and the #gWinProcTreeCr3, #gWinProcTreeUserCr3, and #gWinProcTreeEprocess
/// trees.
/// This function does no cleanup, so if there are any processes inside the list or trees those will not be freed, the
/// hooks placed in their context will not be removed, etc.
///
{
    InitializeListHead(&gWinProcesses);

    RbPreinit(&gWinProcTreeCr3);
    RbInit(&gWinProcTreeCr3, IntWinProcRbTreeNodeFree, IntWinProcRbTreeNodeCompareCr3);

    RbPreinit(&gWinProcTreeUserCr3);
    RbInit(&gWinProcTreeUserCr3, IntWinProcRbTreeNodeFree, IntWinProcRbTreeNodeCompareUserCr3);

    RbPreinit(&gWinProcTreeEprocess);
    RbInit(&gWinProcTreeEprocess, IntWinProcRbTreeNodeFree, IntWinProcRbTreeNodeCompareEproc);
}


void
IntWinProcLstInsertProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Inserts a #WIN_PROCESS_OBJECT structure into the process lists and trees.
///
/// This will add the process to the #gWinProcesses list, and #gWinProcTreeCr3, #gWinProcTreeUserCr3,
/// and #gWinProcTreeEprocess trees.
///
/// @param[in]  Process The process to be inserted.
///
{
    InsertTailList(&gWinProcesses, &Process->Link);

    // Note: we cannot have errors here, because:
    // 1. we supply valid arguments (so no STATUS_INVALID_PARAMETER can occur)
    // 2. at the beginning of the function, we check for duplicates by searching for both the CR3 and EPROCESS (so
    //    we cannot have STATUS_KEY_ALREADY_PRESENT either).
    RbInsertNode(&gWinProcTreeCr3, &Process->NodeCr3);

    RbInsertNode(&gWinProcTreeUserCr3, &Process->NodeUserCr3);

    RbInsertNode(&gWinProcTreeEprocess, &Process->NodeEproc);
}


void
IntWinProcLstRemoveProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Removes a #WIN_PROCESS_OBJECT structure from the process lists and trees.
///
/// This will remove the process from the #gWinProcesses list, and #gWinProcTreeCr3, #gWinProcTreeUserCr3,
/// and #gWinProcTreeEprocess trees.
///
/// @param[in]  Process The process to be removed.
///
{
    RemoveEntryList(&Process->Link);

    RbDeleteNode(&gWinProcTreeCr3, &Process->NodeCr3);

    RbDeleteNode(&gWinProcTreeUserCr3, &Process->NodeUserCr3);

    RbDeleteNode(&gWinProcTreeEprocess, &Process->NodeEproc);
}


PWIN_PROCESS_OBJECT
IntWinProcFindObjectByEprocess(
    _In_ QWORD Eprocess
    )
///
/// @brief      Finds a process by the address of its _EPROCESS structure.
///
/// @param[in]  Eprocess    The guest virtual address of the _EPROCESS structure.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT target;
    RBNODE *result;

    target.EprocessAddress = Eprocess;

    status = RbLookupNode(&gWinProcTreeEprocess, &target.NodeEproc, &result);
    if (INT_SUCCESS(status) && result)
    {
        return CONTAINING_RECORD(result, WIN_PROCESS_OBJECT, NodeEproc);
    }
    else
    {
        return NULL;
    }
}


PWIN_PROCESS_OBJECT
IntWinProcFindObjectByPid(
    _In_ DWORD Pid
    )
///
/// @brief      Finds a process by its ID.
///
/// @param[in]  Pid     Process ID to search for.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    LIST_ENTRY *list;

    list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        if (pProc->Pid == Pid)
        {
            return pProc;
        }

        list = list->Flink;
    }

    return NULL;
}


PWIN_PROCESS_OBJECT
IntWinProcFindObjectByName(
    _In_ CHAR const *Name,
    _In_ BOOLEAN MustBeSystem
    )
///
/// @brief      Finds a process by name.
///
/// @param[in]  Name            NULL-terminated string with the name of the process.
/// @param[in]  MustBeSystem    True if the process must be a system process.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    if (NULL == Name)
    {
        return NULL;
    }

    for (LIST_ENTRY *entry = gWinProcesses.Flink; entry != &gWinProcesses; entry = entry->Flink)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(entry, WIN_PROCESS_OBJECT, Link);

        if (MustBeSystem && !pProc->SystemProcess)
        {
            continue;
        }

        if (!strcasecmp(pProc->Name, Name))
        {
            return pProc;
        }
    }

    return NULL;
}


PWIN_PROCESS_OBJECT
IntWinProcFindObjectByCr3(
    _In_ QWORD Cr3
    )
///
/// @brief      Finds a process by its kernel CR3.
///
/// @param[in]  Cr3     Process kernel CR3 to search for.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT target;
    RBNODE* result;

    target.Cr3 = Cr3;

    status = RbLookupNode(&gWinProcTreeCr3, &target.NodeCr3, &result);
    if (INT_SUCCESS(status) && result)
    {
        return CONTAINING_RECORD(result, WIN_PROCESS_OBJECT, NodeCr3);
    }
    else
    {
        return NULL;
    }
}


PWIN_PROCESS_OBJECT
IntWinProcFindObjectByUserCr3(
    _In_ QWORD Cr3
    )
///
/// @brief      Finds a process by its user CR3.
///
/// If KPTI is not active, or the process has the same CR3 for both kernel and user mode, this is the same as
/// #IntWinProcFindObjectByCr3.
///
/// @param[in]  Cr3     Process user CR3 to search for.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT target;
    RBNODE* result;

    target.UserCr3 = Cr3;

    status = RbLookupNode(&gWinProcTreeUserCr3, &target.NodeUserCr3, &result);
    if (INT_SUCCESS(status) && result)
    {
        return CONTAINING_RECORD(result, WIN_PROCESS_OBJECT, NodeUserCr3);
    }
    else
    {
        return NULL;
    }
}


INTSTATUS
IntWinProcIsPsActiveProcessHead(
    _In_ QWORD Gva
    )
///
/// @brief      Checks if a guest memory area is the list head of the process list (PsActiveProcessHead)
///
/// Gva must point to the ActiveProcessLinks field of the System _EPROCESS.
///
/// The check is based on a series of invariants:
///     - Gva must not be inside the kernel image
///     - The Flink and Blink fields must point in the kernel space.
///     - Flink->Blink and Blink->Flink must point back to Gva.
///     - The _EPROCESS must be readable.
///     - The PID must be 4.
///     - The Type field from the _DISPATCHER_HEADER must be 3.
///     - The process name must be "System".
///
/// @param[in]  Gva Guest virtual address to check.
///
/// @retval     #INT_STATUS_SUCCESS if Gva points to PsActiveProcessHead.
/// @retval     #INT_STATUS_INVALID_OBJECT_TYPE if Gva does not point to PsActiveProcessHead.
///
{
    INTSTATUS status;
    QWORD flink, blink, prevFlink, nextBlink, pid, type;
    CHAR imageName[IMAGE_BASE_NAME_LEN];

#define IS_INVALID_PTR(ptr)     !IS_KERNEL_POINTER_WIN(gGuest.Guest64, (ptr)) ||                                \
                                (gGuest.Guest64 && 0xffffffff00000000 == ((ptr) & 0xffffffff00000000)) ||       \
                                (!gGuest.Guest64 && 0xffffffff == (ptr))                                        \

    // System EPROC is not in kernel
    if (gGuest.KernelVa != 0 &&
        gGuest.KernelSize != 0 &&
        Gva >= gGuest.KernelVa &&
        Gva <= gGuest.KernelVa + gGuest.KernelSize)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    flink = 0;
    blink = 0;
    prevFlink = 0;
    nextBlink = 0;
    pid = 0;
    type = 0;

    status = IntKernVirtMemFetchWordSize(Gva, &flink);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (IS_INVALID_PTR(flink))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    status = IntKernVirtMemFetchWordSize(Gva + gGuest.WordSize, &blink);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (IS_INVALID_PTR(blink))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Make sure flink->blink points to us.
    status = IntKernVirtMemFetchWordSize(flink + gGuest.WordSize, &nextBlink);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (nextBlink != Gva)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Make sure blink->flink points to us.
    status = IntKernVirtMemFetchWordSize(blink, &prevFlink);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (prevFlink != Gva)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    status = IntKernVirtMemFetchWordSize(Gva - WIN_KM_FIELD(Process, ListEntry) + WIN_KM_FIELD(Process, Id), &pid);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (pid != 4)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    status = IntKernVirtMemFetchWordSize(Gva - WIN_KM_FIELD(Process, ListEntry), &type);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if ((BYTE)type != 3)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Process name must be 'System'
    status = IntKernVirtMemRead(Gva - WIN_KM_FIELD(Process, ListEntry) +
                                WIN_KM_FIELD(Process, Name),
                                sizeof(imageName),
                                imageName,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    imageName[sizeof(imageName) - 1] = 0;

    if (0 != strcasecmp(imageName, "system"))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcAdd(
    _In_ QWORD Eprocess,
    _In_ QWORD Aux
    )
///
/// @brief      Adds a new process to the Introcore list of processes.
///
/// This function is used for statically detecting processes that were spawned before Introcore started.
///
/// This does some preliminary checks and then delegates much of the work to #IntWinProcCreateProcessObject.
/// If any of the Delete, Exiting, or VmDeleted flags are set, or if the HasAddrSpace flag is not set, the process
/// is ignored as it is no longer active and won't become active again, but the OS did not remove it from the list
/// of processes yet.
///
/// If possible, this function will try to find the parent of the current process.
///
/// @param[in]  Eprocess    Guest virtual address of the _EPROCESS structure for the new process.
/// @param[in]  Aux         Ignored.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    QWORD cr3, parentEproc;
    DWORD pid;
    DWORD flags;
    WIN_PROCESS_OBJECT *pProcObj, *pParent;
    BYTE *pEproc = NULL;

    UNREFERENCED_PARAMETER(Aux);

    status = IntWinProcMapEprocess(Eprocess, &pEproc);
    if (NULL == pEproc || !INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcMapEprocess failed: 0x%08x\n", status);
        return status;
    }

    pid = *(DWORD *)(pEproc + WIN_KM_FIELD(Process, Id));

    if (gGuest.Guest64)
    {
        cr3 = *(QWORD *)(pEproc + WIN_KM_FIELD(Process, Cr3));
    }
    else
    {
        cr3 = *(DWORD *)(pEproc + WIN_KM_FIELD(Process, Cr3));
    }

    flags = *(DWORD *)(pEproc + WIN_KM_FIELD(Process, Flags));
    if (0 != (flags & (
                  WIN_KM_FIELD(EprocessFlags, Delete)
                  | WIN_KM_FIELD(EprocessFlags, Exiting)
                  | WIN_KM_FIELD(EprocessFlags, VmDeleted))))
    {
        LOG("[EPROCESS] Skipping process %llx which is being marked as deleted (flags = 0x%x)...\n", Eprocess, flags);
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto cleanup_and_exit;
    }
    else if (0 == (flags & WIN_KM_FIELD(EprocessFlags, HasAddrSpace)))
    {
        LOG("[EPROCESS] Skipping process %llx which does not have an address space (flags = 0x%x)...\n",
            Eprocess, flags);
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto cleanup_and_exit;
    }

    if (NULL != IntWinProcFindObjectByEprocess(Eprocess))
    {
        LOG("[EPROCESS] The list seems to have a circular loop on process 0x%016llx, will break iteration...\n",
            Eprocess);
        status = INT_STATUS_BREAK_ITERATION;
        goto cleanup_and_exit;
    }

    // Find the associated parent process.
    pParent = IntWinProcFindObjectByPid(*(DWORD *)(pEproc + WIN_KM_FIELD(Process, ParentPid)));
    if (NULL != pParent)
    {
        parentEproc = pParent->EprocessAddress;
    }
    else
    {
        parentEproc = 0;
    }

    status = IntWinProcCreateProcessObject(&pProcObj, Eprocess, pEproc, parentEproc, 0, cr3, pid, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcCreateProcessObject failed for EPROC 0x%016llx with flags 0x%x: 0x%08x\n",
              Eprocess, flags, status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (NULL != pEproc)
    {
        IntVirtMemUnmap(&pEproc);
    }

    return status;
}


INTSTATUS
IntWinProcIterateGuestProcesses(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief      Iterates the in-guest process list and calls Callback for each entry.
///
/// This function will stop if it iterates more than 10000 entries, as in that case something is most likely wrong.
///
/// @param[in]  Callback    Function to invoke for each entry in the process list.
/// @param[in]  Aux         Optional argument to pass to Callback.
///
/// @retval     #INT_STATUS_SUCCESS in case of success. Note that errors returned by Callback are not propagated and
///             success is still reported.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Callback is NULL.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if PsActiveProcessHead is not set yet.
/// @retval     #INT_STATUS_OUT_OF_RANGE if more than 10000 processes are found in the list.
///
{
#define PROCESSES_MAX_COUNT 65535
    INTSTATUS status;
    QWORD currentProcess = 0, count = 0, nextProcess = 0;

    if (Callback == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    currentProcess = gWinGuest->PsActiveProcessHead;
    if (currentProcess == 0)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    status = IntKernVirtMemRead(currentProcess, gGuest.WordSize, &currentProcess, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the Flink value of EPROCESS @ 0x%016llx: 0x%08x\n", currentProcess, status);
        return status;
    }

    status = IntKernVirtMemRead(currentProcess, gGuest.WordSize, &nextProcess, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the Flink value of EPROCESS @ 0x%016llx: 0x%08x\n", currentProcess, status);
        return status;
    }

    status = INT_STATUS_SUCCESS;
    while ((currentProcess != gWinGuest->PsActiveProcessHead) && (count++ < PROCESSES_MAX_COUNT))
    {
        status = Callback((currentProcess - WIN_KM_FIELD(Process, ListEntry)), Aux);
        if (INT_STATUS_BREAK_ITERATION == status)
        {
            status = INT_STATUS_SUCCESS;
            break;
        }
        if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            // The process was not actually added in our list, so decrease the count so that we don't
            // miss the actually non-deleted processes.
            count--;
        }

        status = IntKernVirtMemRead(currentProcess, gGuest.WordSize, &currentProcess, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the Flink value of EPROCESS @ 0x%016llx: 0x%08x\n", currentProcess, status);
            break;
        }

        // Consider the nextProcess variable as the hare in the tortoise and hare algorithm. We should do f(f(hare)),
        // so read the next eprocess of the next eprocess, keeping the notion that the "nextProcess" moves through
        // the list at a speed doubled of the "currentProcess"'s speed.
        status = IntKernVirtMemRead(nextProcess, gGuest.WordSize, &nextProcess, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the Flink value of EPROCESS @ 0x%016llx: 0x%08x\n", nextProcess, status);
            break;
        }

        status = IntKernVirtMemRead(nextProcess, gGuest.WordSize, &nextProcess, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the Flink value of EPROCESS @ 0x%016llx: 0x%08x\n", nextProcess, status);
            break;
        }

        // The hare and the tortoise are in the same position - a cycle was detected in the list! Verify if the cycle
        // is not the list head (since the linked lists will always be cyclical with respect to the list head). Note
        // that we don't actually need to find the first repetition in the cycle, nor the period of the cycle, we only
        // need to find whether it is a cycle, so the condition that the hare and the tortoise are in the same position
        // is enough.
        if (nextProcess == currentProcess && currentProcess != gWinGuest->PsActiveProcessHead)
        {
            ERROR("[ERROR] The guest linked list seem to be cyclical, a cycle has been detected on 0x%016llx\n",
                  currentProcess);
            status = INT_STATUS_INVALID_DATA_STATE;
            break;
        }
    }

    if (count >= PROCESSES_MAX_COUNT)
    {
        status = INT_STATUS_OUT_OF_RANGE;
    }

    return status;

#undef PROCESSES_MAX_COUNT
}


INTSTATUS
IntWinProcGetNameFromEprocess(
    _In_ QWORD Eprocess,
    _Out_writes_z_(IMAGE_BASE_NAME_LEN) CHAR *Name
    )
///
/// @brief      Reads a process name from the guest memory.
///
/// This reads the name from the _EPROCESS ImageFileName field. If the process name has more than 15 characters, only
/// the first 15 characters will be available.
///
/// @param[in]  Eprocess    The guest virtual address of the _EPROCESS structure.
/// @param[out] Name        On success, will contain a NULL-terminated string with the process name. Must be at least
///                         #IMAGE_BASE_NAME_LEN in size.
///
/// @returns    A pointer to a #WIN_PROCESS_OBJECT for the found process, or NULL if no process exists.
///
{
    if (0 == Eprocess)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    memset(Name, 0, IMAGE_BASE_NAME_LEN);

    _Analysis_assume_(Name[IMAGE_BASE_NAME_LEN - 1] = NULL);
    return IntKernVirtMemRead(Eprocess + WIN_KM_FIELD(Process, Name),
                              IMAGE_BASE_NAME_LEN - 1,
                              Name,
                              NULL);
}


INTSTATUS
IntWinProcGetNameFromInternalEprocess(
    _In_ QWORD Eprocess,
    _Out_writes_z_(IMAGE_BASE_NAME_LEN) CHAR *Name
    )
///
/// @brief      Get a process name from the internal Introcore buffers.
///
/// @param[in]  Eprocess    The guest virtual address of the _EPROCESS structure.
/// @param[out] Name        On success, will contain a NULL-terminated string with the process name. Must be at least
///                         #IMAGE_BASE_NAME_LEN in size.
///
/// @retval     #INT_STATUS_SUCCESS if a process was found for the provided _EPROCESS address.
/// @retval     #INT_STATUS_NOT_FOUND if no process was found.
///
{
    LIST_ENTRY *list;

    list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);
        list = list->Flink;

        if (pProc->EprocessAddress == Eprocess)
        {
            memcpy(Name, pProc->Name, IMAGE_BASE_NAME_LEN);
            _Analysis_assume_(Name[IMAGE_BASE_NAME_LEN - 1] = NULL);

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


BOOLEAN
IntWinProcIsEnoughHeapAvailable(
    void
    )
///
/// @brief      Checks if enough heap is available in order to protect a new process.
///
/// We consider that enough memory is available if a percentage of #MIN_HEAP_SIZE_PERCENT is free from the total
/// amount of available memory.
///
/// @returns    True if enough memory is available, False if not.
///
{
    INTSTATUS status;
    size_t totalHeapSize, freeHeapSize;

    // Before actually protecting the process, make sure enough heap is available. If there's less than 30%, we will NOT
    // protect anymore processes!!!
    status = IntQueryHeapSize(&totalHeapSize, &freeHeapSize);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntQueryHeapSize failed: 0x%08x, will assume 'infinite' heap.\n", status);
        totalHeapSize = 0xFFFFFFFFFFFFFFFF;
        freeHeapSize  = 0xFFFFFFFFFFFFFFFF;
    }

    TRACE("[INFO] Heap stats: total size: %zu bytes, free: %zu bytes\n", totalHeapSize, freeHeapSize);

    // Make sure more than minimum of MIN_HEAP_SIZE_PERCENT of heap is available.
    if (freeHeapSize < (totalHeapSize * MIN_HEAP_SIZE_PERCENT) / 100)
    {
        return FALSE;
    }

    return TRUE;
}


_Function_class_(FUNC_RbTreeNodeFree) void
IntWinProcRbTreeNodeFree(
    _Inout_ RBNODE *Node
    )
///
/// @brief      The NodeFree routine for the process RBTREE structures.
///
{
    UNREFERENCED_PARAMETER(Node);
}


_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareCr3(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right)
{
    WIN_PROCESS_OBJECT const *p1 = CONTAINING_RECORD(Left, WIN_PROCESS_OBJECT, NodeCr3);
    WIN_PROCESS_OBJECT const *p2 = CONTAINING_RECORD(Right, WIN_PROCESS_OBJECT, NodeCr3);
    QWORD cr3p1, cr3p2;

    cr3p1 = p1->Cr3;
    cr3p2 = p2->Cr3;

    if (cr3p1 < cr3p2)
    {
        return -1;
    }
    else if (cr3p1 > cr3p2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareUserCr3(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right)
{
    PWIN_PROCESS_OBJECT p1 = CONTAINING_RECORD(Left, WIN_PROCESS_OBJECT, NodeUserCr3);
    PWIN_PROCESS_OBJECT p2 = CONTAINING_RECORD(Right, WIN_PROCESS_OBJECT, NodeUserCr3);
    QWORD cr3p1, cr3p2;

    cr3p1 = p1->UserCr3;
    cr3p2 = p2->UserCr3;

    if (cr3p1 < cr3p2)
    {
        return -1;
    }
    else if (cr3p1 > cr3p2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareEproc(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right)
{
    PWIN_PROCESS_OBJECT p1 = CONTAINING_RECORD(Left, WIN_PROCESS_OBJECT, NodeEproc);
    PWIN_PROCESS_OBJECT p2 = CONTAINING_RECORD(Right, WIN_PROCESS_OBJECT, NodeEproc);

    if (p1->EprocessAddress < p2->EprocessAddress)
    {
        return -1;
    }
    else if (p1->EprocessAddress > p2->EprocessAddress)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


INTSTATUS
IntWinProcGetAgentsAsCli(
    _Out_writes_bytes_(Length) PCHAR CommandLine,
    _In_ DWORD Length
    )
///
/// @brief      Returns the name and ID for all the processes injected as agents inside the guest.
///
/// This is useful for the killer agent.
///
/// @param[out] CommandLine On success, will contain a NULL-terminated string with the names and IDs of the agent
///                         processes.
/// @param[in]  Length      The size of the CommandLine buffer.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL if there is not enough space in the CommandLine buffer.
///
{
    PCHAR cmd = CommandLine;

    PLIST_ENTRY list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);
        INT32 len;

        list = list->Flink;

        if (!pProc->IsAgent)
        {
            continue;
        }

        len = snprintf(cmd, Length, "%s %u ", pProc->Name, pProc->Pid);
        if (len < 0)
        {
            return INT_STATUS_INVALID_DATA_VALUE;
        }

        if ((DWORD)len >= Length)
        {
            return INT_STATUS_DATA_BUFFER_TOO_SMALL;
        }

        Length -= len;
        cmd += len;
    }

    return INT_STATUS_SUCCESS;
}


void
IntWinProcDump(
    void
    )
///
/// @brief      Prints information about all the processes in the system.
///
{
    INTSTATUS status;

    LIST_ENTRY *list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc;
        CHAR parentName[IMAGE_BASE_NAME_LEN];
        CHAR realParentName[IMAGE_BASE_NAME_LEN];

        memset(parentName, 0, sizeof(parentName));
        memset(realParentName, 0, sizeof(realParentName));

        pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        if (0 != pProc->ParentEprocess)
        {
            status = IntWinProcGetNameFromInternalEprocess(pProc->ParentEprocess, parentName);
            if (INT_STATUS_NOT_FOUND == status)
            {
                strlcpy(parentName, "<TERMINATED>", sizeof(parentName));
            }
        }

        if (0 != pProc->RealParentEprocess)
        {
            status = IntWinProcGetNameFromInternalEprocess(pProc->RealParentEprocess, realParentName);
            if (INT_STATUS_NOT_FOUND == status)
            {
                strlcpy(parentName, "<TERMINATED>", sizeof(parentName));
            }
        }

        NLOG("    EPROCESS: 0x%016llx, CR3: 0x%016llx, PID: %d, Token: 0x%016llx, WOW64: %d, Name: %s, "
             "Parent: 0x%016llx/%s, Real parent: 0x%016llx/%s, Prot Mask: 0x%08x, System: %d\n",
             pProc->EprocessAddress,
             pProc->Cr3,
             pProc->Pid,
             pProc->OriginalTokenPtr,
             pProc->Wow64Process,
             pProc->Name,
             pProc->ParentEprocess,
             parentName,
             pProc->RealParentEprocess,
             realParentName,
             pProc->ProtectionMask,
             pProc->SystemProcess);

        if (NULL != pProc->Subsystemx64)
        {
            LIST_ENTRY *list2;

            NLOG("        64 bit subsystem:\n");

            // Dump loaded modules
            list2 = pProc->Subsystemx64->ProcessModules.Flink;
            while (list2 != &pProc->Subsystemx64->ProcessModules)
            {
                PWIN_PROCESS_MODULE pMod = CONTAINING_RECORD(list2, WIN_PROCESS_MODULE, Link);

                list2 = list2->Flink;

                NLOG("            MODULE : 0x%016llx, Size: 0x%08x, Protected: %d, Hooked: %d, Unpack Protected: %d, "
                     "Main Module: %d Path: \"%s\", hash: 0x%08x\n",
                     pMod->VirtualBase, pMod->Size, pMod->ShouldProtHooks,
                     pMod->IsProtected, pMod->ShouldProtUnpack, pMod->IsMainModule,
                     utf16_for_log(pMod->Path->Path), pMod->Path->NameHash);
            }
        }


        if (NULL != pProc->Subsystemx86)
        {
            LIST_ENTRY *list2;

            NLOG("        32 bit subsystem:\n");

            // Dump loaded modules.
            list2 = pProc->Subsystemx86->ProcessModules.Flink;
            while (list2 != &pProc->Subsystemx86->ProcessModules)
            {
                PWIN_PROCESS_MODULE pMod = CONTAINING_RECORD(list2, WIN_PROCESS_MODULE, Link);

                list2 = list2->Flink;

                NLOG("            MODULE : 0x%016llx, Size: 0x%08x, Protected: %d, Hooked: %d, "
                     "Unpack Protected: %d, Main Module: %d Path: \"%s\"\n",
                     pMod->VirtualBase, pMod->Size, pMod->ShouldProtHooks,
                     pMod->IsProtected, pMod->ShouldProtUnpack, pMod->IsMainModule, utf16_for_log(pMod->Path->Path));
            }
        }

        NLOG("        VAD tree:\n");

        // Dump the VAD tree.
        IntWinVadWalkTree(pProc, (PFUNC_RbTreeWalkCallback)IntWinVadDump);

        NLOG("        VAS monitor:\n");

        IntVasDump(pProc->Cr3);
    }
}


void
IntWinProcDumpVads(
    _In_opt_ const char *ProcessName
    )
///
/// @brief      Prints information about the VADs loaded in a process.
///
/// @param[in]  ProcessName NULL-terminated string with a process name. May be NULL. If it is not NULL, only the
///             processes with a matching name will be printed.
///
{
    LIST_ENTRY *list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);
        list = list->Flink;

        if (NULL != ProcessName && 0 != strcasecmp(ProcessName, pProc->Name))
        {
            continue;
        }

        NLOG("Process %s:%d @ 0x%016llx\n", pProc->Name, pProc->Pid, pProc->EprocessAddress);
        IntWinVadWalkTree(pProc, (PFUNC_RbTreeWalkCallback)IntWinVadDump);
    }
}


void
IntWinProcDumpEgFlags(
    void
    )
///
/// @brief      Prints the mitigation flags of a process.
///
{
    if ((0 == WIN_KM_FIELD(Process, MitigationFlags)) || 0 == (WIN_KM_FIELD(Process, MitigationFlags2)))
    {
        LOG("Mitigation Flags are not available! 0x%08x 0x%08x\n",
            WIN_KM_FIELD(Process, MitigationFlags),
            WIN_KM_FIELD(Process, MitigationFlags2));

        return;
    }

    LIST_ENTRY *list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);
        INTSTATUS status;
        WIN_MITIGATION_FLAGS flags = { 0 };
        WIN_MITIGATION_FLAGS2 flags2 = { 0 };
        static const PCHAR flagsText[] =
        {
            "ControlFlowGuardEnabled",
            "ControlFlowGuardExportSuppressionEnabled",
            "ControlFlowGuardStrict",
            "DisallowStrippedImages",
            "ForceRelocateImages",
            "HighEntropyASLREnabled",
            "StackRandomizationDisabled",
            "ExtensionPointDisable",
            "DisableDynamicCode",
            "DisableDynamicCodeAllowOptOut",
            "DisableDynamicCodeAllowRemoteDowngrade",
            "AuditDisableDynamicCode",
            "DisallowWin32kSystemCalls",
            "AuditDisallowWin32kSystemCalls",
            "EnableFilteredWin32kAPIs",
            "AuditFilteredWin32kAPIs",
            "DisableNonSystemFonts",
            "AuditNonSystemFontLoading",
            "PreferSystem32Images",
            "ProhibitRemoteImageMap",
            "AuditProhibitRemoteImageMap",
            "ProhibitLowILImageMap",
            "AuditProhibitLowILImageMap",
            "SignatureMitigationOptIn",
            "AuditBlockNonMicrosoftBinaries",
            "AuditBlockNonMicrosoftBinariesAllowStore",
            "LoaderIntegrityContinuityEnabled",
            "AuditLoaderIntegrityContinuity",
            "EnableModuleTamperingProtection",
            "EnableModuleTamperingProtectionNoInherit",
        };
        static const PCHAR flags2Text[] =
        {
            "EnableExportAddressFilter",
            "AuditExportAddressFilter",
            "EnableExportAddressFilterPlus",
            "AuditExportAddressFilterPlus",
            "EnableRopStackPivot",
            "AuditRopStackPivot",
            "EnableRopCallerCheck",
            "AuditRopCallerCheck",
            "EnableRopSimExec",
            "AuditRopSimExec",
            "EnableImportAddressFilter",
            "AuditImportAddressFilter",
        };

        list = list->Flink;

        status = IntKernVirtMemRead(pProc->EprocessAddress + WIN_KM_FIELD(Process, MitigationFlags),
                                    sizeof(flags),
                                    &flags,
                                    NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            continue;
        }

        status = IntKernVirtMemRead(pProc->EprocessAddress + WIN_KM_FIELD(Process, MitigationFlags2),
                                    sizeof(flags2),
                                    &flags2,
                                    NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            continue;
        }

        LOG("Dumping Flags for `%s` @ 0x%016llx\n", pProc->Name, pProc->EprocessAddress);
        NLOG("+ Mitigation Flags: 0x%08x\n", flags.Flags);
        for (DWORD i = 0; i < 32; i++)
        {
            if (0 == (flags.Flags & (1 << i)))
            {
                continue;
            }

            if (i >= ARRAYSIZE(flagsText))
            {
                NLOG("\t Bit %02d is set -> UNKNOWN\n", i);
            }
            else
            {
                NLOG("\t Bit %02d is set -> %s\n", i, flagsText[i]);
            }
        }
        NLOG("\n");
        NLOG("+ Mitigation Flags 2: 0x%08x\n", flags2.Flags);
        for (DWORD i = 0; i < 32; i++)
        {
            if (0 == (flags2.Flags & (1 << i)))
            {
                continue;
            }

            if (i >= ARRAYSIZE(flags2Text))
            {
                NLOG("\t Bit %02d is set -> UNKNOWN\n", i);
            }
            else
            {
                NLOG("\t Bit %02d is set -> %s\n", i, flags2Text[i]);
            }
        }

        NLOG("\n\n");
    }
}


INTSTATUS
IntWinProcMapEprocess(
    _In_ QWORD Eprocess,
    _Outptr_ void **Ptr
    )
///
/// @brief      Maps a _EPROCESS structure.
///
/// This will map the minimum necessary size for Introcore to parse an _EPROCESS. #IntVirtMemUnmap must be used to
/// unmap a mapped process.
///
/// @param[in]  Eprocess    Guest virtual address of the _EPROCESS structure to be mapped.
/// @param[out] Ptr         On success, will contain a pointer to the mapped memory.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    // must be initialized because compiler assumes gGuest.WordSize might be 0
    INTSTATUS status = INT_STATUS_UNINITIALIZED_STATUS_VALUE;
    static DWORD sizeofNeededEprocess = 0;

    if (0 == Eprocess)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Ptr)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // While sizeof(EPROCESS) < PAGE_SIZE - (aprox.) 0x20, the entire structure will be allocated in the same
    // page so we can map just the remaining page. However, an attacker might craft an EPROCESS structure at
    // page boundary. This ensures that all of our accesses inside the mapped EPROCESS are safe but it does
    // not fully detect EPROCESS structures that span two pages because the size we check is the maximum field
    // offset + guest word size, not the actual size of EPROCESS!
    if (0 == sizeofNeededEprocess)
    {
        for (WIN_KM_FIELD_PROCESS field = 0; field < winKmFieldProcessEnd; ++field)
        {
            if (sizeofNeededEprocess < gWinGuest->OsSpecificFields.Km.Process[field])
            {
                sizeofNeededEprocess = gWinGuest->OsSpecificFields.Km.Process[field];
            }
        }
        // now sizeofNeededEprocess is just the highest field offset, add word size
        sizeofNeededEprocess += gGuest.WordSize;
    }

    // It seems that `sizeofNeededEprocess += gGuest.WordSize;` causes some problems on certain OSes, for
    // example on a 2k12R2, sizeof(EPROCESS) is 0x700. The last field is the ExitStatus DWORD (at 0x6FC).
    // We will want to read 0x704, but if it is cross-page and the second page isn't present, we will fail.
    // Thus, until we have all the fields sizes in CAMI, we will try to decrement at most gGuest.WordSize / 2 times
    // and retry the mapping. If it succeeds, then that is our real size.
    for (BYTE i = 0; i <= gGuest.WordSize / 2; i++)
    {
        status = IntVirtMemMap(Eprocess, sizeofNeededEprocess, gGuest.Mm.SystemCr3, 0, Ptr);
        if (INT_SUCCESS(status))
        {
            break;
        }

        sizeofNeededEprocess--;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to map EPROCESS at address 0x%016llx, IntVirtMemMap failed: 0x%08x\n", Eprocess, status);
    }

    return status;
}
