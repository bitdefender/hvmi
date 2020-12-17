/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixprocess.h"
#include "alerts.h"
#include "crc32.h"
#include "hook.h"
#include "icache.h"
#include "lixcrash.h"
#include "lixfiles.h"
#include "lixmm.h"
#include "lixcred.h"
#include "lixvdso.h"
#include "kernvm.h"
#include "lixksym.h"
#include "lixcmdline.h"

#define LIX_MM_PROT_MASK                BIT(63) ///< The bit used to mark a memory space as protected.

///
/// @brief This structure contains control bits for linux process logging.
///
typedef struct _LIX_TASK_LOG
{
    DWORD KmThreads: 1;     ///< If the kernel threads events should be logged.

    DWORD UmThreads: 1;     ///< If the user mode threads events should be logged.
    DWORD Forks: 1;         ///< If forks should be logged.
    DWORD Execs: 1;         ///< If exec events should be logged.

    DWORD ProtUmThreads: 1; ///< If events related to threads created by protected process should be logged.
    DWORD ProtForks: 1;     ///< If forks performed by protected processes should be logged.
    DWORD ProtExecs: 1;     ///< If an exec performed by a protected process should be logged.
} LIX_TASK_LOG;


///
/// @brief The global structure controlling linux process logging.
///
/// By default, on debug builds everything is logged, while on release builds only protected processes events
/// are logged.
///
LIX_TASK_LOG gLixTaskLogLevel =
{
#if defined(DEBUG)
    .KmThreads = 1,
    .UmThreads = 1,
    .Forks = 1,
    .Execs = 1,
#endif

    .ProtUmThreads = 1,
    .ProtForks = 1,
    .ProtExecs = 1,
};


///
/// @brief Linux processes signaling that the guest OS is shutting down.
///
static const char *gLixTerminatingTasks[] =
{
    "S90reboot",
    "systemd-shutdown",
    "reboot",
    "shutdown"
};


///
/// @brief The list with all tasks inside the guest OS.
///
static LIST_HEAD gLixTasks = LIST_HEAD_INIT(gLixTasks);

///
/// @brief The list with all tasks that are currently protected.
///
static LIST_HEAD gLixProtectedTasks = LIST_HEAD_INIT(gLixProtectedTasks);

///
/// @brief The list with all tasks that should be protected.
///
static LIST_HEAD gLixTasksToProtect = LIST_HEAD_INIT(gLixTasksToProtect);


///
/// @brief #list_for_next wrapper used to iterate tasks from a given node.
///
#define for_next_task(_task, _var_name)     list_for_next(_task, gLixTasks, LIX_TASK_OBJECT, _var_name)

///
/// @brief #list_for_each wrapper used to iterate Linux tasks.
///
#define for_each_task(_var_name)            list_for_each(gLixTasks, LIX_TASK_OBJECT, _var_name)

///
/// @brief #list_for_each wrapper used to iterate protected tasks.
///
#define for_each_protected_task(_var_name)  list_for_each_link(gLixProtectedTasks, LIX_TASK_OBJECT, \
                                                               ExploitProtProcLink, _var_name)

///
/// @brief #list_for_each wrapper used to iterate tasks that should be protected.
///
#define for_each_task_to_protect(_var_name) list_for_each(gLixTasksToProtect, LIX_PROTECTED_PROCESS, _var_name)


///
/// @brief The list with all cached paths.
///
static LIST_HEAD gLixTaskPaths = LIST_HEAD_INIT(gLixTaskPaths);

///
/// @brief #list_for_each wrapper used to iterate cached paths.
///
#define for_each_path(_var_name)        list_for_each(gLixTaskPaths, LIX_TASK_PATH, _var_name)



char *
basename_s(char *path, size_t len)
///
/// @brief Returns a pointer inside a path string pointing to the beginning of the file base name.
///
/// @param[in] path A string containing a sanitized Unix path.
/// @param[in] len  The length of the path parameter.
///
/// @returns The file base name with the associated path.
///
{
    size_t i;

    if (len == 0)
    {
        return path;
    }

    for (i = len - 1; i && (path[i] != '/'); i--);

    return path + i + !!(path[i] == '/');
}


void
sanitize_path(char *path, size_t len, size_t *new_len)
///
/// @brief Sanitizes an Unix path by removing trailing path delimiters.
///
/// @param[in]  path    A string containing a Unix path.
/// @param[in]  len     The length of the path parameter.
/// @param[out] new_len Will contain the new size of the sanitized path.
///
{
    size_t i = len - 1;

    for (; i && path[i] == '/'; i--)
    {
        len--;
        path[i] = 0;
    }

    *new_len = len;
}


static LIX_TASK_PATH *
IntLixTaskPathGetRef(
    _In_ LIX_TASK_PATH *Path
    )
///
/// @brief Increases the reference counter for a LIX_TASK_PATH object.
///
/// @param[in] Path Pointer to a LIX_TASK_PATH object.
///
/// @returns The same LIX_TASK_PATH object sent as Path parameter.
///
{
    if (__likely(Path))
    {
        ++Path->RefCount;
    }

    return Path;
}


static LIX_TASK_PATH *
IntLixTaskPathGetByDentry(
    _In_opt_ QWORD FileGva,
    _In_opt_ QWORD PathGva,
    _In_ QWORD DentryGva
    )
///
/// @brief Get the LIX_TASK_PATH object associated with a given path.
///
/// This function will initially try to return an existing #LIX_TASK_PATH object. If the dentry was not yet cached
/// then a new object is created (based on which of the FileGva or PathGva parameter is set) and inserted in
/// the #gLixTaskPaths list.
///
/// This function will also increment the object reference counter.
///
/// @param[in] FileGva   The guest virtual address of the "file" structure.
/// @param[in] PathGva   The guest virtual address of the path string.
/// @param[in] DentryGva The guest virtual address of the "dentry" structure.
///
/// @returns A pointer to a LIX_TASK_PATH object associated with the given dentry.
/// @returns NULL If a valid path could not be fetched.
///
{
    INTSTATUS status;
    char *path = NULL;
    DWORD len = 0;
    BOOLEAN allocPath = FALSE;

    for_each_path(pPath)
    {
        if (pPath->DentryGva == DentryGva)
        {
            return IntLixTaskPathGetRef(pPath);
        }
    }

    if (FileGva)
    {
        status = IntLixFileGetPath(FileGva, &path, &len);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixFileGetPath failed for %llx: %08x\n", FileGva, status);
            return NULL;
        }

        allocPath = TRUE;
    }
    else if (PathGva)
    {
        status = IntReadString(PathGva, 2, FALSE, &path, &len);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntReadString failed for %llx: %08x\n", PathGva, status);
            return NULL;
        }
    }
    else
    {
        return NULL;
    }

    LIX_TASK_PATH *pPath = HpAllocWithTag(sizeof(*pPath), IC_TAG_PATH);
    if (NULL == pPath)
    {
        return NULL;
    }

    pPath->DentryGva = DentryGva;
    pPath->RefCount = 1;
    pPath->PathLength = len;

    if (allocPath)
    {
        pPath->Path = HpAllocWithTag((size_t)len + 1ull, IC_TAG_NAME);
        if (NULL == pPath->Path)
        {
            HpFreeAndNullWithTag(&pPath, IC_TAG_PATH);
            return NULL;
        }

        memcpy(pPath->Path, path, len + 1ull);
    }
    else
    {
        pPath->Path = path;
    }

    pPath->Name = basename_s(pPath->Path, (size_t)len);
    pPath->NameLength = strlen(pPath->Name);

    InsertTailList(&gLixTaskPaths, &pPath->Link);

    return pPath;
}


static LIX_TASK_PATH *
IntLixTaskPathGetByFile(
    _In_ QWORD FileGva
    )
///
/// @brief Get a #LIX_TASK_PATH object based on the guest virtual address of a "file" structure.
///
/// @param[in] FileGva The guest virtual address of a "file" structure.
///
/// @returns A #LIX_TASK_PATH object associated with the "file" structure.
///
{
    QWORD dentry;

    INTSTATUS status = IntLixFileGetDentry(FileGva, &dentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileGetDentry failed for file %llx: %08x\n", FileGva, status);
        return NULL;
    }

    return IntLixTaskPathGetByDentry(FileGva, 0, dentry);
}


static LIX_TASK_PATH *
IntLixTaskPathGetByPath(
    _In_ QWORD PathGva,
    _In_ QWORD DentryGva
    )
///
/// @brief Get a #LIX_TASK_PATH object based on the guest virtual address of a path string.
///
/// @param[in] PathGva   The guest virtual address of the path string.
/// @param[in] DentryGva The guest virtual address of the "dentry" structure.
///
/// @returns A #LIX_TASK_PATH object associated with the path string and "dentry" structure.
///
{
    return IntLixTaskPathGetByDentry(0, PathGva, DentryGva);
}


static void
IntLixTaskPathFree(
    _Inout_ LIX_TASK_PATH **Path
    )
///
/// @brief Release a #LIX_TASK_PATH object.
///
/// This function will firstly decrement the object reference count. If the counter becomes zero, then the object
/// is destroyed and the memory will be freed.
///
/// @param[in] Path Pointer to a LIX_TASK_PATH reference.
///
{
    LIX_TASK_PATH *pPath = *Path;

    if (NULL == pPath)
    {
        return;
    }

    *Path = NULL;

    if (--pPath->RefCount)
    {
        return;
    }

    RemoveEntryList(&pPath->Link);

    if (pPath->Path)
    {
        HpFreeAndNullWithTag(&pPath->Path, IC_TAG_NAME);
    }

    HpFreeAndNullWithTag(&pPath, IC_TAG_PATH);
}


static BOOLEAN
IntLixTaskMustLog(
    _In_ const LIX_TASK_OBJECT *Task,
    _In_ BOOLEAN Protected
    )
///
/// @brief Controls whether information about a task must be logged or not.
///
/// @param[in] Task      Pointer to a #LIX_TASK_OBJECT.
/// @param[in] Protected Set if the Task sent as a parameter is being protected.
///
/// @returns TRUE  If information about the given task must be logged.
/// @returns FALSE Otherwise.
///
{
    if (Task->KernelMode)
    {
        // NOTE: Protection is not set for these for now, nothing else to check
        return gLixTaskLogLevel.KmThreads != 0;
    }
    else if (Task->IsThread)
    {
        return (gLixTaskLogLevel.UmThreads || (Protected && gLixTaskLogLevel.ProtUmThreads));
    }
    else if (Task->Exec)
    {
        return (gLixTaskLogLevel.Execs || (Protected && gLixTaskLogLevel.ProtExecs));
    }
    else
    {
        return (gLixTaskLogLevel.Forks || (Protected && gLixTaskLogLevel.ProtForks));
    }
}


INTSTATUS
IntLixGetInitTask(
    _Out_ QWORD *InitTask
    )
///
/// @brief Finds the guest virtual address of the "init_task".
///
/// Searches the linux kernel for the 'init_task' variable. This variable can be exported in kallsyms but some distros
/// (Debian) disable variable exporting in kallsyms, and we must do it our way then.
///
/// @param[out] InitTask Will contain, upon successful return, the guest virtual address of "init_task" variable.
///
/// @returns #INT_STATUS_SUCCESS             On success.
/// @returns #INT_STATUS_INVALID_PARAMETER_1 If InitTask parameter does not point to a valid memory location.
/// @returns #INT_STATUS_NOT_FOUND           If the address of the init task could not be found.
///
{
    INTSTATUS status;

    if (NULL == InitTask)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // It should be there, except on Debian 8
    *InitTask = IntKsymFindByName("init_task", NULL);
    if (*InitTask)
    {
        return INT_STATUS_SUCCESS;
    }

    for (QWORD startGva = gLixGuest->Layout.DataStart & PAGE_MASK;
         startGva < gLixGuest->Layout.DataEnd;
         startGva += PAGE_SIZE)
    {
        BYTE *p;
        BOOLEAN found = FALSE;

        status = IntVirtMemMap(startGva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx 0x%08x\n", startGva, status);
            continue;
        }

        for (QWORD ts = startGva; ts < startGva + PAGE_SIZE; ts += sizeof(QWORD))
        {
            QWORD parent, mm, signal;
            DWORD offset = ts & PAGE_OFFSET;
            char comm[LIX_COMM_SIZE] = {0};

            // 1. init_task->real_parent = init_task
            if (offset + LIX_FIELD(TaskStruct, RealParent) + 8 > PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(ts + LIX_FIELD(TaskStruct, RealParent), &parent);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVirtMemFetchQword failed: 0x%08x\n", status);
                    continue;
                }
            }
            else
            {
                parent = *(QWORD *)(p + offset + LIX_FIELD(TaskStruct, RealParent));
            }

            if (parent != ts)
            {
                continue;
            }

            // 2. init_task->parent = init_task
            if (offset + LIX_FIELD(TaskStruct, Parent) + 8 > PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(ts + LIX_FIELD(TaskStruct, RealParent), &parent);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
                    continue;
                }
            }
            else
            {
                parent = *(QWORD *)(p + offset + LIX_FIELD(TaskStruct, Parent));
            }

            if (parent != ts)
            {
                continue;
            }

            // 3. init_task->mm = 0
            if (offset + LIX_FIELD(TaskStruct, Mm) + 8 > PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(ts + LIX_FIELD(TaskStruct, Mm), &mm);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
                          ts + LIX_FIELD(TaskStruct, Mm), status);
                    continue;
                }
            }
            else
            {
                mm = *(QWORD *)(p + offset + LIX_FIELD(TaskStruct, Mm));
            }

            if (0 != mm)
            {
                continue;
            }

            // 4. init_task->signal = kernel_ptr
            if (offset + LIX_FIELD(TaskStruct, Signal) + 8 > PAGE_SIZE)
            {
                status = IntKernVirtMemFetchQword(ts + LIX_FIELD(TaskStruct, Signal), &signal);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
                    continue;
                }
            }
            else
            {
                signal = *(QWORD *)(p + offset + LIX_FIELD(TaskStruct, Signal));
            }

            if (!IS_KERNEL_POINTER_LIX(signal))
            {
                continue;
            }

            // 5. init_task->comm starts with 'swapper'
            status = IntKernVirtMemRead(ts + LIX_FIELD(TaskStruct, Comm), sizeof(comm), comm, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed reading process name @ 0x%016llx: 0x%08x\n",
                      ts + LIX_FIELD(TaskStruct, Comm), status);
                continue;
            }

            // Here we don't really want to include the NULL terminator because we are only interested in matching
            // the "swapper" pattern. It may or may not transform into something like "swapper/0".
            if (0 != memcmp(comm, "swapper", sizeof("swapper") - 1))
            {
                continue;
            }

            comm[sizeof(comm) - 1] = 0;

            TRACE("[LIXTASK] Found init_task @ 0x%016llx with name %s\n", ts, comm);

            *InitTask = ts;

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


static QWORD gTaskMapped = 0;
static BYTE *gTaskPtr1 = NULL;
static BYTE *gTaskPtr2 = NULL;


static INTSTATUS
_IntLixTaskStartMap(
    _In_ QWORD TaskGva
    )
///
/// @brief Map the task_struct in order to perform further reads from it without any overhead.
///
/// NOTE: We can not use the mechanism from lixfastread.c because it will interleave with the VMA filling who is
/// also using it.
///
/// @param[in] TaskGva The guest virtual address of the "task_struct" structure.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns The status returned by #IntVirtMemMap if a mapping error occurs.
///
{
    INTSTATUS status;

    gTaskMapped = TaskGva;

    status = IntVirtMemMap(gTaskMapped, PAGE_REMAINING(TaskGva), gGuest.Mm.SystemCr3, 0, &gTaskPtr1);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", gTaskMapped, status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
_IntLixTaskRead(
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _Out_ void *Buffer)

///
/// @brief Perform a read from the previously mapped "task_struct" structure.
///
/// @param[in]  Offset The offset inside "task_struct" structure from where the read should be performed.
/// @param[in]  Size   The size in bytes to be read from the "task_struct".
/// @param[out] Buffer The buffer where the read outcome will be stored.
///
/// @returns INT_STATUS_SUCCESS on success.
/// @returns INT_STATUS_INVALID_INTERNAL_STATE if this function call was not preceded by an #_IntLixTaskStartMap call.
///
{
    if (NULL == gTaskPtr1 || !IS_KERNEL_POINTER_LIX(gTaskMapped))
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    // NOTE: Should we validate the offset ?! I think that's beyond the scope of this function...

    QWORD gva = gTaskMapped + Offset;

    if (PAGE_COUNT(gTaskMapped, (QWORD)Offset + Size) > 1)
    {
        DWORD remaining = Size;

        if (PAGE_FRAME_NUMBER(gTaskMapped) == PAGE_FRAME_NUMBER(gva))
        {
            DWORD toRead = PAGE_REMAINING(gva);

            memcpy(Buffer, gTaskPtr1 + Offset, toRead);

            remaining -= toRead;
        }

        if (NULL == gTaskPtr2)
        {
            QWORD nextPage = (gTaskMapped + PAGE_SIZE) & PAGE_MASK;

            INTSTATUS status = IntVirtMemMap(nextPage, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &gTaskPtr2);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", nextPage, status);
                return status;
            }
        }

        memcpy((BYTE *)Buffer + (Size - remaining), gTaskPtr2 + ((gva + Size - remaining) & PAGE_OFFSET), remaining);
    }
    else
    {
        // The whole it's in the first page
        memcpy(Buffer, gTaskPtr1 + Offset, Size);
    }

    return INT_STATUS_SUCCESS;
}


static void
_IntLixTaskFinishMap(
    void
    )
///
/// @brief Unmaps a previously mapped "task_struct".
///
{
    IntVirtMemUnmap(&gTaskPtr1);

    if (gTaskPtr2)
    {
        IntVirtMemUnmap(&gTaskPtr2);
    }

    gTaskPtr1 = NULL;
    gTaskPtr2 = NULL;

    gTaskMapped = 0;
}


static INTSTATUS
IntLixTaskFetchMm(
    _In_opt_ QWORD MmStruct,
    _In_ LIX_TASK_OBJECT *Task,
    _In_opt_ LIX_TASK_OBJECT *Parent
    )
///
/// @brief Fetches the CR3 of a Linux task.
///
/// This function will find the CR3 value associated with the supplied task based on it's features, as follows:
///
/// 1. If the task is a kernel thread, then no CR3 is associated with it.
/// 2. If the task is an user land thread then it inherits the parent CR3.
/// 3. If the task is not a thread then the translation of the pgd value residing in the mm structure will be considered
/// the CR3.
///
/// Note: If MmStruct parameter is not supplied then the mm guest virtual address will be fetched from the task
/// currently mapped with #_IntLixTaskStartMap. Thus, make sure the right task is currently mapped if you are not going
/// to supply this parameter.
///
/// @param[in] MmStruct The guest virtual address of the task's mm structure.
/// @param[in] Task     The Linux task.
/// @param[in] Parent   The parent task.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT        If the task supplied is a kernel thread.
/// @returns #INT_STATUS_INVALID_OBJECT_TYPE    If any attempt to extract a valid guest virtual address for the mm
///                                             structure or it's corresponding CR3 fails.
///
{
    INTSTATUS status;
    QWORD mmGva, pgd;

    if (Task->KernelMode)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == MmStruct)
    {
        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Mm), sizeof(mmGva), &mmGva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Fetching mm failed in task 0x%016llx: 0x%08x\n", Task->Gva, status);
            return status;
        }
    }
    else
    {
        mmGva = MmStruct;
    }

    if (!IS_KERNEL_POINTER_LIX(mmGva))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    Task->MmGva = mmGva;

    if (Parent && Parent->MmGva == mmGva)
    {
        Task->Cr3 = Parent->Cr3;

        return INT_STATUS_SUCCESS;
    }

    status = IntKernVirtMemFetchQword(mmGva + LIX_FIELD(MmStruct, Pgd), &pgd);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              mmGva + LIX_FIELD(MmStruct, Pgd), status);
        goto _cleanup_and_exit;
    }

    if (!IS_KERNEL_POINTER_LIX(pgd))
    {
        ERROR("[ERROR] The PGD 0x%016llx @ 0x%016llx (offset %x) is not a valid one!\n",
              pgd, mmGva + LIX_FIELD(MmStruct, Pgd), LIX_FIELD(MmStruct, Pgd));

        status = INT_STATUS_INVALID_OBJECT_TYPE;

        goto _cleanup_and_exit;
    }

    status = IntTranslateVirtualAddress(pgd, gGuest.Mm.SystemCr3, &Task->Cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed translating PGD 0x%016llx: 0x%08x\n", pgd, status);
        Task->Cr3 = 0;
    }

    status = INT_STATUS_SUCCESS;

_cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        Task->Cr3 = 0;
    }

    return status;
}


INTSTATUS
IntLixTaskGetCurrentTaskStruct(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *TaskStruct
    )
///
/// @brief Reads the guest virtual address of the task currently running on a CPU.
///
/// @param[in]  CpuNumber  The CPU number.
/// @param[out] TaskStruct Will contain, upon successful return, the guest virtual address of the task currently
///             running on the given CPU.
///
/// @returns #INT_STATUS_SUCCESS             On success.
/// @returns #INT_STATUS_INVALID_OBJECT_TYPE If invalid values of either gs base or current are read from guest.
///
{
    INTSTATUS status;
    QWORD gsBase;
    QWORD current;

    if (TaskStruct == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (CpuNumber == IG_CURRENT_VCPU)
    {
        CpuNumber = gVcpu->Index;
    }

    status = IntGsRead(CpuNumber, &gsBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGsRead failed for cpu %d: 0x%08x.\n", CpuNumber, status);
        return status;
    }

    if (!IS_KERNEL_POINTER_LIX(gsBase))
    {
        WARNING("[WARNING] 'gs' for cpu %d is not in kernel mode: %llx\n", CpuNumber, gsBase);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    status = IntKernVirtMemFetchQword(gsBase + gLixGuest->OsSpecificFields.CurrentTaskOffset, &current);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemPatchQword failed for gva 0x%llx with status: 0x%08x\n",
              gsBase + gLixGuest->OsSpecificFields.CurrentTaskOffset, status);
        return status;
    }

    if (__unlikely(!IS_KERNEL_POINTER_LIX(current) || (current % 8)))
    {
        ERROR("[ERROR] Current task 0x%016llx is not valid!\n", current);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    *TaskStruct = current;

    return INT_STATUS_SUCCESS;
}


LIX_TASK_OBJECT *
IntLixTaskGetCurrent(
    _In_ DWORD CpuNumber
    )
///
/// @brief Finds the task that is currently running on the given CPU.
///
/// This function will read the value of "current_task" from the per-cpu memory region and will return the
/// #LIX_TASK_OBJECT corresponding to the read value. Even though at any given time there will be a task running
/// on a CPU, it is not guaranteed that there is a #LIX_TASK_OBJECT associated to it. (e.g. idle tasks)
///
/// @param[in] CpuNumber The CPU number.
///
/// @returns The #LIX_TASK_OBJECT associated with the task running on the given CPU.
/// @returns NULL If this operation fails.
///
{
    QWORD currentTs;

    INTSTATUS status = IntLixTaskGetCurrentTaskStruct(CpuNumber, &currentTs);
    if (!INT_SUCCESS(status))
    {
        return NULL;
    }

    return IntLixTaskFindByGva(currentTs);
}


static __forceinline QWORD
IntLixUserToKernelPgd(
    _In_ QWORD Pgd
    )
///
/// @brief Translates the value of a user page global directory to it's corresponding kernel value when KPTI is active.
///
/// @param[in] Pgd The guest physical address of the page global directory.
///
/// @returns The guest physical address of the kernel copy of the page global directory.
///
{
    return Pgd & ~(BIT(LIX_PTI_PGTABLE_SWITCH_BIT));
}


static __forceinline QWORD
IntLixKernelToUserPgd(
    _In_ QWORD Pgd
    )
///
/// @brief Translates the value of a kernel page global directory to it's corresponding user value when KPTI is active.
///
/// @param[in] Pgd The guest physical address of the page global directory.
///
/// @returns The guest physical address of the user copy of the page global directory.
///
{
    return Pgd | BIT(LIX_PTI_PGTABLE_SWITCH_BIT);
}


QWORD
IntLixGetKernelCr3(
    _In_ QWORD Cr3
    )
///
/// @brief Transforms an user CR3 into a kernel CR3 on systems with KPTI enabled and active.
///
/// @param[in] Cr3 The user CR3 value.
///
/// @returns The kernel CR3 obtain from the user value.
///
{
    Cr3 &= CR3_LONG_MODE_MASK;

    if (!gGuest.KptiActive)
    {
        return Cr3;
    }

    return IntLixUserToKernelPgd(Cr3);
}


LIX_TASK_OBJECT *
IntLixTaskFindByCr3(
    _In_ QWORD Cr3
    )
///
/// @brief Finds the Linux process having the provided Cr3.
///
/// @param[in] Cr3 The CR3 value.
///
/// @returns A pointer to the #LIX_TASK_OBJECT of the task with the supplied Cr3 value.
/// @returns NULL If the task was not found.
///
{
    if (0 == Cr3)
    {
        return NULL;
    }

    Cr3 = CLEAN_PHYS_ADDRESS64(IntLixGetKernelCr3(Cr3));

    for_each_task(pTask)
    {
        if (pTask->Cr3 == Cr3)
        {
            return pTask;
        }
    }

    return NULL;
}


LIX_TASK_OBJECT *
IntLixTaskProtFindByMm(
    _In_ QWORD MmGva
    )
///
/// @brief Finds the protected Linux process having the provided mm guest virtual address.
///
/// @param[in] MmGva The guest virtual address of a mm struct.
///
/// @returns A pointer to the #LIX_TASK_OBJECT of the protected task with the supplied mm guest virtual address.
/// @returns NULL If the task was not found.
///
{
    for_each_protected_task(pTask)
    {
        if (pTask->MmGva == MmGva)
        {
            return pTask;
        }
    }

    return NULL;
}


LIX_TASK_OBJECT *
IntLixTaskFindByMm(
    _In_ QWORD MmGva
    )
///
/// @brief Finds the Linux process having the provided mm guest virtual address.
///
/// @param[in] MmGva The guest virtual address of a mm struct.
///
/// @returns A pointer to the #LIX_TASK_OBJECT of the task with the supplied mm guest virtual address.
/// @returns NULL If the task was not found.
///

{
    for_each_task(pTask)
    {
        if (pTask->MmGva == MmGva)
        {
            return pTask;
        }
    }

    return NULL;
}


LIX_TASK_OBJECT *
IntLixTaskFindByGva(
    _In_ QWORD TaskStruct
    )
///
/// @brief Finds Linux process with the provided "task_struct" guest virtual address.
///
/// @param[in] TaskStruct The guest virtual address of the "task_struct".
///
/// @returns A pointer to the #LIX_TASK_OBJECT of the task with the supplied "task_struct" guest virtual address.
/// @returns NULL If the task was not found.
///

{
    for_each_task(pTask)
    {
        if (pTask->Gva == TaskStruct)
        {
            return pTask;
        }
    }

    return NULL;
}


LIX_TASK_OBJECT *
IntLixTaskFindByPid(
    _In_ DWORD Pid
    )
///
/// @brief Finds the Linux process having the provided PID.
///
/// @param[in] Pid The task PID.
///
/// @returns A pointer to the #LIX_TASK_OBJECT of the task with the supplied PID.
/// @returns NULL If the task was not found.
///

{
    for_each_task(pTask)
    {
        if (pTask->Pid == Pid)
        {
            return pTask;
        }
    }

    return NULL;
}


DWORD
IntLixTaskGetExecCount(
    void
    )
///
/// @brief Returns the number of processes that have performed an exec.
///
{
    DWORD count = 0;
    for_each_task(pTask)
    {
        if (pTask->Exec)
        {
            ++count;
        }
    }

    return count;
}


INTSTATUS
IntLixTaskGetTrapFrame(
    _In_ const LIX_TASK_OBJECT *Task,
    _Out_ LIX_TRAP_FRAME *TrapFrame
    )
///
/// @brief Retrieves the trap frame for a Linux task.
///
/// The kernel implementation for this function is the following:
///
/// \#define task_pt_regs(task)
/// ({
///     unsigned long __ptr = (unsigned long)task_stack_page(task);
///     __ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
///     ((struct pt_regs *)__ptr) - 1;
/// })
///
/// Note: On x86_64 configurations TOP_OF_KERNEL_STACK_PADDING is zero so it can be ignored.
///
/// @param[in]  Task      The Linux task.
/// @param[out] TrapFrame Upon successful return will be filled with with the trap frame of the supplied task.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD trapFrameGva, kmStack;

    status = IntKernVirtMemFetchQword(Task->Gva + LIX_FIELD(TaskStruct, Stack), &kmStack);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read km stack pointer for task %s (%d 0x%llx). Status: 0x%08x\n",
              Task->Comm, Task->Pid, Task->Gva, status);
        return status;
    }

    trapFrameGva = kmStack + LIX_FIELD(Info, ThreadSize) - sizeof(*TrapFrame);

    memzero(TrapFrame, sizeof(*TrapFrame));

    return IntKernVirtMemRead(trapFrameGva, sizeof(*TrapFrame), TrapFrame, NULL);
}


static LIX_PROTECTED_PROCESS *
IntLixTaskShouldProtect(
    _In_ const LIX_TASK_OBJECT *Task
    )
///
/// @brief Checks whether a Linux task should be protected or not.
///
/// @param[in] Task The Linux task.
///
/// @returns Pointer to a #LIX_PROTECTED_PROCESS structure whose glob pattern matches the task path, name, or comm,
/// if the  task should be protected. NULL if the supplied task shouldn't to be protected.
///
{
    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_MISC_PROCS))
    {
        return NULL;
    }

    for_each_task_to_protect(pProt)
    {
        if ((pProt->NamePattern && Task->Path && IntMatchPatternUtf8(pProt->NamePattern, Task->Path->Name, 0)) ||
            IntMatchPatternUtf8(pProt->CommPattern, Task->Comm, INTRO_MATCH_TRUNCATED))
        {
            return pProt;
        }
    }

    return NULL;
}


void
IntLixProcUpdateProtectedProcess(
    _In_ const void *Name,
    _In_ const CAMI_STRING_ENCODING Encoding,
    _In_ const CAMI_PROT_OPTIONS *Options
    )
///
/// @brief Updates the protection flags for Linux tasks that should be protected based on options received via CAMI.
///
/// @param[in] Name     The name (or glob pattern) of the task to be protected whose options should be patched.
/// @param[in] Encoding The encoding type of the Name string parameter. Currently only CAMI_STRING_ENCODING_UTF8 are
///                     supported for Linux tasks.
/// @param[in] Options  The CAMI_PROT_OPTIONS which should by applied for processes matching the supplied Name.
///
{
    if (Encoding != CAMI_STRING_ENCODING_UTF8)
    {
        WARNING("[WARNING] Unsupported string encoding: %d\n", Encoding);
        return;
    }

    for_each_task_to_protect(pProcess)
    {
        if (IntMatchPatternUtf8(Name, pProcess->CommPattern, 0))
        {
            pProcess->Protection.Current = pProcess->Protection.Original & ~(Options->ForceOff);
            pProcess->Protection.Beta = Options->ForceBeta;
            pProcess->Protection.Feedback = Options->ForceFeedback;

            TRACE("[CAMI] Protected process info updated. Original : 0x%llx, Current : 0x%llx, "
                  "Beta : 0x%llx, Feedback : 0x%llx", pProcess->Protection.Original, pProcess->Protection.Current,
                  pProcess->Protection.Beta, pProcess->Protection.Feedback);
        }
    }
}


static INTSTATUS
IntLixTaskDeactivateExploitProtection(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Deactivates exploit protection for a Linux task.
///
/// @param[in] Task The Linux task.
///
/// @returns #INT_STATUS_SUCCESS         On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If the task supplied is not protected against exploits.
///
{
    INTSTATUS status;
    QWORD flags;

    if (!(Task->Protection.Mask & PROC_OPT_PROT_EXPLOIT))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Invalidate all the entries inside the ICACHE associated to this process,
    // since the CR3 will not be hooked anymore.
    status = IntIcFlushVaSpace(gGuest.InstructionCache, Task->Cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIcFlushVaSpace failed: 0x%08x\n", status);
    }

    IntLixMmDestroyVmas(Task);

    status = IntKernVirtMemFetchQword(Task->MmGva + LIX_FIELD(MmStruct, Flags), &flags);
    if (!INT_SUCCESS(status))
    {
        CRITICAL("[ERROR] IntKernVirtMemFetchQword failed for mm %llx: %08x\n", Task->MmGva, status);
    }
    else
    {
        flags &= ~LIX_MM_PROT_MASK;

        // NOTE: IntVirtMemSafeWrite should be used instead, but it will induce significant performance penalty.
        status = IntKernVirtMemPatchQword(Task->MmGva + LIX_FIELD(MmStruct, Flags), flags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemPatchQword failed for mm %llx: %08x\n", Task->MmGva, status);
        }
    }

    if (Task->HookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Task->HookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: %08x", status);
        }
    }

    RemoveEntryList(&Task->ExploitProtProcLink);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskActivateExploitProtection(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Activates exploit protection for a Linux task.
///
/// This function will decide if the supplied task should be protected (it's protection mask activates
/// exploit protection) and then will enable exploit protection. Static detected tasks that are dying
/// are ignored.
///
/// @param[in] Task The Linux task.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If the task does not have to be protected.
///
{
    INTSTATUS status;
    QWORD flags;

    if (!(Task->Protection.Mask & PROC_OPT_PROT_EXPLOIT))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == Task->Cr3)
    {
        ERROR("[ERROR] Requesting to protect process '%s' (%d, %llx, %llx)but it has no CR3 (mm 0x%016llx)!\n",
              Task->ProcName, Task->Pid, Task->Gva, Task->Cr3, Task->MmGva);
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    if (Task->StaticDetected)
    {
        // This shouldn't happen since we ignore tasks which have PF_EXITING flag set.
        // But it's better to do it anyway.
        DWORD mmUsers = 0, mmCount = 0;

        status = IntKernVirtMemFetchDword(Task->MmGva + LIX_FIELD(MmStruct, MmUsers), &mmUsers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting mm_users: %08x\n", status);
            goto _protect_task;
        }

        status = IntKernVirtMemFetchDword(Task->MmGva + LIX_FIELD(MmStruct, MmCount), &mmCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting mm_count: %08x\n", status);
            goto _protect_task;
        }

        if (0 == mmUsers || 0 == mmCount)
        {
            WARNING("[WARNING] Process %s (%d, %llx, %llx) has a dying mm @ %llx: (%d, %d)!\n",
                    Task->Comm, Task->Pid, Task->Gva, Task->Cr3, Task->MmGva, mmUsers, mmCount);

            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }

_protect_task:
    status = IntHookObjectCreate(introObjectTypeUmGenericNxZone, Task->Cr3, &Task->HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: %08x\n", status);
        return status;
    }

    status = IntLixMmPopulateVmas(Task);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmPopulateVmas failed: 0x%08x\n", status);
        goto _free_and_exit;
    }

    InsertTailList(&gLixProtectedTasks, &Task->ExploitProtProcLink);

    status = IntKernVirtMemFetchQword(Task->MmGva + LIX_FIELD(MmStruct, Flags), &flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for mm %llx: %08x\n", Task->MmGva, status);
        goto _free_and_exit;
    }

    flags |= LIX_MM_PROT_MASK;

    // NOTE: IntVirtMemSafeWrite should be used instead, but it will induce significant performance penalty.
    status = IntKernVirtMemPatchQword(Task->MmGva + LIX_FIELD(MmStruct, Flags), flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemPatchQword failed for mm %llx: %08x\n", Task->MmGva, status);
        goto _free_and_exit;
    }

    status = INT_STATUS_SUCCESS;

_free_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntLixTaskDeactivateExploitProtection(Task);
    }

    return status;
}


static INTSTATUS
IntLixTaskActivateProtection(
    _In_ LIX_TASK_OBJECT *Task,
    _In_opt_ LIX_TASK_OBJECT *Parent
    )
///
/// @brief Activates protection for a Linux process.
///
/// @param[in] Task   The Linux process.
/// @param[in] Parent The process parent.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT  If the process should not be protected.
/// @returns #INT_STATUS_INVALID_INTERNAL_STATE If an error occurred.
///
{
    INTSTATUS status;
    BOOLEAN sameCr3;

    if (Task->Interpreter)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_MISC_PROCS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // No point in checking the list if the Task is actually a thread/fork. The task name can be
    // anything, so the threads/forks should inherit the parent's protection.
    if (Task->Exec)
    {
        const LIX_PROTECTED_PROCESS *pProt = IntLixTaskShouldProtect(Task);

        if (NULL != pProt)
        {
            Task->Protection.Mask = pProt->Protection.Current;
            Task->Protection.Beta = pProt->Protection.Beta;
            Task->Protection.Feedback = pProt->Protection.Feedback;
            Task->Context = pProt->Context;
        }
        else
        {
            Task->Protection.Mask = 0;
            Task->Context = 0;
        }

        Task->RootProtectionMask = Task->Protection.Mask;
    }
    else if (Parent)
    {
        // A thread/fork should inherit the parent's root protection.
        // This is for a special case where a thread does fork, because
        // the thread protection mask will not include PROC_OPT_PROT_EXPLOIT
        Task->Protection.Mask = Parent->RootProtectionMask;
        Task->Protection.Beta = Parent->Protection.Beta;
        Task->Protection.Feedback = Parent->Protection.Feedback;

        Task->RootProtectionMask = Parent->RootProtectionMask;
        Task->Context = Parent->Context;
    }

    if (0 == Task->Protection.Mask)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    sameCr3 = Parent && (Task->Cr3 == Parent->Cr3);

    // Clean the protection flags (for example, if the parent & child share the same CR3, then
    // it's pointless to activate protection again on the same CR3).
    if (sameCr3)
    {
        /// Only protections that are CR3-dependent should be removed!
        Task->Protection.Mask &= ~PROC_OPT_PROT_EXPLOIT;
        Task->Protection.Mask &= ~PROC_OPT_PROT_CORE_HOOKS;
    }

    status = IntLixTaskActivateExploitProtection(Task);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Process '%s' (%d, %llx, %llx) will not be exploit-protected: %08x!\n",
              Task->ProcName, Task->Pid, Task->Gva, Task->Cr3, status);

        Task->Protection.Mask &= ~PROC_OPT_PROT_EXPLOIT;

        status = INT_STATUS_SUCCESS;
    }

    // Keep the threads as protected... But mark the processes that failed to activate
    // the given protection as !protected
    if (!sameCr3 && (Task->Protection.Mask == 0))
    {
        ERROR("[ERROR] Task %s, 0x%016llx failed to activate any protection!\n", Task->Comm, Task->Gva);

        Task->Protected = FALSE;

        if (INT_SUCCESS(status))
        {
            status = INT_STATUS_INVALID_INTERNAL_STATE;
        }

        return status;
    }

    if (IntLixTaskMustLog(Task, TRUE))
    {
        TRACE("[PROC] Activated protection %llx for '%s' (%d, %llx, %llx)\n",
              Task->Protection.Mask, Task->ProcName, Task->Pid, Task->Gva, Task->Cr3);
    }

    Task->Protected = TRUE;

    return INT_STATUS_SUCCESS;
}


static void
IntLixTaskDeactivateProtection(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Deactivates protection for a Linux process.
///
/// @param[in] Task The Linux process.
///
{
    INTSTATUS status;

    if (!Task->Protected)
    {
        return;
    }

    status = IntLixTaskDeactivateExploitProtection(Task);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Process '%s' (%d, %llx, %llx) failed to deactivate protection: %08x\n",
                Task->ProcName, Task->Pid, Task->Gva, Task->Cr3, status);
    }

    if (IntLixTaskMustLog(Task, TRUE))
    {
        LOG("[PROC] Deactivated protection for %s '%s' (%d, %llx, %llx)!\n",
            Task->IsThread ? "thread" : "process", Task->ProcName,
            Task->Pid, Task->Gva, Task->Cr3);
    }

    Task->Protection.Mask = 0;
    Task->RootProtectionMask = 0;
    Task->Context = 0;
    Task->Protected = FALSE;
}


static INTSTATUS
IntLixTaskFetchCmdLine(
    _In_ LIX_TASK_OBJECT *Process,
    _In_ QWORD BinprmGva
    )
///
/// @brief Fetches the command line for a Linux process on the exec() system call.
///
/// @param[in] Process   The Linux process.
/// @param[in] BinprmGva The guest virtual address of the binprm structure holding the exec info.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_INVALID_DATA_STATE     If an inconsistency is detected inside OS specific fields.
/// @returns #INT_STATUS_NOT_FOUND              If the command line could not be fetched.
/// @returns #INT_STATUS_INSUFFICIENT_RESOURCES If not enough memory is available to store the command line.
{
    INTSTATUS status;
    QWORD vmaStart, vmaEnd, iter, file;
    DWORD argc, curLength, allocationSize;
    BYTE *pMapping = NULL;

    status = IntVirtMemMap(BinprmGva, LIX_FIELD(Binprm, Sizeof), gGuest.Mm.SystemCr3, 0, &pMapping);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %llx: 0x%08x\n", BinprmGva, status);
        return status;
    }

    argc = *(DWORD *)(pMapping + LIX_FIELD(Binprm, Argc));
    file = *(QWORD *)(pMapping + LIX_FIELD(Binprm, Vma));

    IntVirtMemUnmap(&pMapping);

    status = IntVirtMemMap(file,
                           MAX(LIX_FIELD(Vma, VmaStart), LIX_FIELD(Vma, VmaEnd)) + sizeof(QWORD),
                           gGuest.Mm.SystemCr3,
                           0,
                           &pMapping);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %llx: 0x%08x\n", file, status);
        return status;
    }

    vmaStart = *(QWORD *)(pMapping + LIX_FIELD(Vma, VmaStart));
    vmaEnd = *(QWORD *)(pMapping + LIX_FIELD(Vma, VmaEnd));

    IntVirtMemUnmap(&pMapping);

    if ((vmaStart | vmaEnd) & PAGE_OFFSET)
    {
        ERROR("[ERROR] VMA limits are not PAGE_SIZE aligned: start=0x%llx end = 0x%llx", vmaStart, vmaEnd);
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (vmaStart >= vmaEnd)
    {
        ERROR("[ERROR] Start of vma_struct %llx is bigger or equal that the end %llx!\n", vmaStart, vmaEnd);
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (vmaEnd - vmaStart > ONE_GIGABYTE)
    {
        ERROR("[ERROR] Argpage VMA is to big: 0x%llu. Cmdline will not be fetched\n", vmaEnd - vmaStart);
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    // Skip pages which are not present
    for (iter = vmaStart;
         iter < vmaEnd && (!INT_SUCCESS(IntVirtMemMap(iter, PAGE_SIZE, Process->Cr3, 0, &pMapping)));
         iter += PAGE_SIZE) { }

    if ((iter >= vmaEnd) || NULL == pMapping)
    {
        ERROR("[ERROR] Could not read cmdline. Not a single page from VMA 0x%llx to 0x%llx is present!\n",
              vmaStart, vmaEnd);
        return INT_STATUS_NOT_FOUND;
    }

    // vmaEnd - vmaStart is always <= 1GB
    allocationSize = (DWORD)(vmaEnd - iter);

    Process->CmdLine = HpAllocWithTag(allocationSize, IC_TAG_PCMD);
    if (NULL == Process->CmdLine)
    {
        IntVirtMemUnmap(&pMapping);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    curLength = 0;
    for (;;)
    {
        DWORD parsed = 0;
        while ((0 == curLength) && (parsed < PAGE_SIZE) && (0 == pMapping[parsed]))
        {
            parsed++;
        }

        while (parsed < PAGE_SIZE)
        {
            if (0 == pMapping[parsed])
            {
                argc--;
                if (0 == argc)
                {
                    break;
                }
                Process->CmdLine[curLength] = ' ';
            }
            else
            {
                Process->CmdLine[curLength] = pMapping[parsed];
            }

            parsed++;
            curLength++;
        }

        IntVirtMemUnmap(&pMapping);

        if (0 == argc)
        {
            break;
        }

        iter += PAGE_SIZE;
        if (iter >= vmaEnd)
        {
            WARNING("[WARNING] Reached end of vma, but there are %d more args to be read!\n", argc);
            break;
        }

        status = IntVirtMemMap(iter, PAGE_SIZE, Process->Cr3, 0, &pMapping);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed: %08x\n", status);
            break;
        }
    }

    // Avoid the off-by-one if the commandline page is corrupted.
    if (curLength >= allocationSize)
    {
        curLength = allocationSize - 1;
    }

    Process->CmdLine[curLength] = 0;
    Process->CmdLineLength = curLength;

    return INT_STATUS_SUCCESS;
}


static void
IntLixTaskSetProcName(
    _Inout_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Sets the name for a Linux process
///
/// This function will set the process name depending what info is available(path or comm).
///
/// @param[in] Task The Linux process.
///
{
    if (Task->Path)
    {
        Task->ProcName = Task->Path->Path;
        Task->ProcNameLength = (DWORD)Task->Path->PathLength;
    }
    else
    {
        Task->ProcName = Task->Comm;
        Task->ProcNameLength = strlen(Task->Comm);
    }
}


static void
IntLixTaskGetPath(
    _In_ QWORD FileGva,
    _In_ QWORD DPathGva,
    _Out_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Read and set the path for a Linux process.
///
/// @param[in]  FileGva  The guest virtual address of the "file" structure associated with the executed file.
/// @param[in]  DPathGva The guest virtual address of the "d_path" function call result.
/// @param[out] Task     The Linux process.
///
{
    INTSTATUS status = IntLixFileGetDentry(FileGva, &Task->ExeFileDentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileGetDentry failed for %llx: %08x\n", FileGva, status);
        return;
    }

    if (!IS_ERR(DPathGva) && DPathGva)
    {
        Task->Path = IntLixTaskPathGetByPath(DPathGva, Task->ExeFileDentry);
    }

    if (NULL == Task->Path)
    {
        Task->Path = IntLixTaskPathGetByDentry(FileGva, 0, Task->ExeFileDentry);
    }
}


static INTSTATUS
IntLixTaskCreateFromBinprm(
    _In_ LIX_TASK_OBJECT *OriginalTask,
    _In_ QWORD BinprmGva,
    _In_ QWORD PathGva,
    _Out_ LIX_TASK_OBJECT *UpdatedTask
    )
///
/// @brief Updates the contents of a previously forked process from it's new linux_binprm (used by the loader).
///
/// @param[in]  OriginalTask The Linux process that performed the exec() system call.
/// @param[in]  BinprmGva    The guest virtual address of the "linux_binprm" structure describing this operation.
/// @param[in]  PathGva      The guest virtual address of the path string.
/// @param[out] UpdatedTask  The Linux process that will be updated upon successful return based on the supplied binprm.
///
/// @returns    #INT_STATUS_SUCCESS On success.
/// @returns    #INT_STATUS_INVALID_PARAMETER_2 If the supplied binprm address does not point to a valid kernel memory
///             location.
///
{
    INTSTATUS status;
    QWORD pathGva, interpGva;
    DWORD pid;

    BYTE *pBinprm;
    int exitSignal;

    if (!IS_KERNEL_POINTER_LIX(BinprmGva))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    UpdatedTask->ActualParent = OriginalTask->Parent;
    UpdatedTask->AgentTag     = OriginalTask->AgentTag;
    UpdatedTask->Context      = OriginalTask->Context;
    UpdatedTask->CreationTime = OriginalTask->CreationTime;
    UpdatedTask->Gva          = OriginalTask->Gva;
    UpdatedTask->IsThread     = FALSE;
    UpdatedTask->KernelMode   = FALSE;
    UpdatedTask->Parent       = OriginalTask->Parent;
    UpdatedTask->RealParent   = OriginalTask->RealParent;
    UpdatedTask->Tgid         = OriginalTask->Tgid;
    UpdatedTask->Pid          = OriginalTask->Pid;

    memcpy(UpdatedTask->Comm, OriginalTask->Comm, sizeof(UpdatedTask->Comm));

    pBinprm = NULL;

    UpdatedTask->ReExecToSelf = FALSE;

    status = IntVirtMemMap(BinprmGva, LIX_FIELD(Binprm, Sizeof), gGuest.Mm.SystemCr3, 0, &pBinprm);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx: 0x%08x\n", BinprmGva, status);
        goto _cleanup_and_exit;
    }

    status = _IntLixTaskStartMap(UpdatedTask->Gva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] _IntLixTaskStartMap failed for task %llx: 0x%08x\n", UpdatedTask->Gva, status);
        goto _cleanup_and_exit;
    }

    {
        DWORD in;

        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, InExecve), sizeof(in), &in);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] _IntLixTaskRead failed for %llx: %08x\n",
                  UpdatedTask->Gva + LIX_FIELD(TaskStruct, InExecve), status);
        }
        else if (0 == (in & BIT(LIX_FIELD(TaskStruct, InExecveBit))))
        {
            ERROR("[ERROR][CRITICAL] in_execve is not in fact set: 0x%02x\n", in);
        }
    }

    status = IntLixTaskFetchMm(*(QWORD *)(pBinprm + LIX_FIELD(Binprm, Mm)), UpdatedTask, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskFetchMm failed for %s: 0x%08x. The process cannot be protected!\n",
              UpdatedTask->ProcName, status);
    }

    IntLixTaskGetPath(*(QWORD *)(pBinprm + LIX_FIELD(Binprm, File)), PathGva, UpdatedTask);

    pathGva = *(QWORD *)(pBinprm + LIX_FIELD(Binprm, Filename));
    interpGva = *(QWORD *)(pBinprm + LIX_FIELD(Binprm, Interp));

    if (interpGva && interpGva != pathGva)
    {
        status = IntReadString(interpGva, 2, FALSE, &UpdatedTask->Interpreter, &UpdatedTask->InterpLength);
        if (!INT_SUCCESS(status))
        {
            UpdatedTask->Interpreter = NULL;
            UpdatedTask->InterpLength = 0;
        }
    }

    // The new exec process can change PID if it assumes the role of group leader
    status = _IntLixTaskRead(LIX_FIELD(TaskStruct, ExitSignal), sizeof(exitSignal), &exitSignal);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the PID from task_struct %llx: %08x\n",
              UpdatedTask->Gva + LIX_FIELD(TaskStruct, Pid), status);
    }
    else if (exitSignal < 0)
    {
        // This means that a thread is doing an exec, so get the PID of the group leader (which can be dead by now)
        QWORD groupLeader;

        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, GroupLeader), sizeof(groupLeader), &groupLeader);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the group_leader from task_struct %llx: %08x\n",
                  UpdatedTask->Gva + LIX_FIELD(TaskStruct, GroupLeader), status);
        }
        else
        {
            LIX_TASK_OBJECT *pGroupLeader = IntLixTaskFindByGva(groupLeader);
            if (NULL == pGroupLeader)
            {
                status = IntKernVirtMemFetchDword(groupLeader + LIX_FIELD(TaskStruct, Pid), &pid);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchDword failed for %llx: %08x\n",
                          groupLeader + LIX_FIELD(TaskStruct, Pid), status);
                }
            }
            else
            {
                pid = pGroupLeader->Pid;
            }

            if (UpdatedTask->Pid != pid)
            {
                TRACE("[INFO] Process '%s' changes PID from %d to %d\n", UpdatedTask->ProcName, UpdatedTask->Pid, pid);

                UpdatedTask->Pid = pid;
            }
        }
    }

    if (OriginalTask->ExeFileDentry == UpdatedTask->ExeFileDentry)
    {
        UpdatedTask->ReExecToSelf = TRUE;
    }

    if ((!UpdatedTask->ReExecToSelf) && OriginalTask->Interpreter && UpdatedTask->Interpreter)
    {
        if (OriginalTask->InterpLength == UpdatedTask->InterpLength &&
            0 == strcmp(OriginalTask->Interpreter, UpdatedTask->Interpreter))
        {
            UpdatedTask->ReExecToSelf = TRUE;
        }
    }

    IntLixTaskSetProcName(UpdatedTask);

    InitializeListHead(&UpdatedTask->Vmas);

    InitializeListHead(&UpdatedTask->ExploitProtProcLink);

    status = IntLixCredAdd(*(QWORD *)(pBinprm + LIX_FIELD(Binprm, Cred)), &UpdatedTask->Creds);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCredAdd failed for %s (%d 0x%llx). Status: 0x%08x\n",
              UpdatedTask->Comm, UpdatedTask->Pid, UpdatedTask->Gva, status);
        UpdatedTask->Creds = NULL;
    }

    _IntLixTaskFinishMap();

    status = INT_STATUS_SUCCESS;

_cleanup_and_exit:
    IntVirtMemUnmap(&pBinprm);

    return status;
}


static void
IntLixTaskSendTaskEvent(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ DWORD ExitCode,
    _In_ BOOLEAN Created,
    _In_ BOOLEAN Crashed,
    _In_ BOOLEAN StaticDetected
    )
///
/// @brief Sends a process event.
///
/// @param[in] Task           The Linux process.
/// @param[in] ExitCode       The process exit code.
/// @param[in] Created        TRUE if the the process is created.
/// @param[in] Crashed        TRUE if the process crashed.
/// @param[in] StaticDetected TRUE if the process was detected statically.
///
{
    INTSTATUS status;
    EVENT_PROCESS_EVENT *pProcEvent;
    LIX_TASK_OBJECT *pParent;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_PROCESSES))
    {
        return;
    }

    if (Created && Task->ReExecToSelf)
    {
        return;
    }

    pProcEvent = &gAlert.Process;
    memzero(pProcEvent, sizeof(*pProcEvent));

    pProcEvent->Created = Created;
    pProcEvent->Protected = Task->Protected != 0;
    pProcEvent->Crashed = Crashed;
    pProcEvent->ExitStatus = ExitCode;

    if (!StaticDetected)
    {
        IntAlertFillLixCurrentProcess(&pProcEvent->CurrentProcess);
    }
    else
    {
        pProcEvent->CurrentProcess.Valid = FALSE;
    }

    IntAlertFillLixProcess(Task, &pProcEvent->Child);

    pParent = IntLixTaskFindByGva(Task->Parent);
    if (pParent)
    {
        IntAlertFillLixProcess(pParent, &pProcEvent->Parent);
    }
    else
    {
        pProcEvent->Parent.Valid = FALSE;
    }

    status = IntNotifyIntroEvent(introEventProcessEvent, pProcEvent, sizeof(*pProcEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static void
IntLixTaskSendAgentEvent(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ DWORD ExitCode,
    _In_ BOOLEAN Created
    )
///
/// @brief Sends an agent event.
///
/// @param[in] Task     The Linux process associated with the agent.
/// @param[in] ExitCode The agent exit code.
/// @param[in] Created  TRUE If the agent has just been created.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_AGENT_EVENT *pAgentEvent;

    if (!Task->AgentTag)
    {
        return;
    }

    pAgentEvent = &gAlert.Agent;
    memzero(pAgentEvent, sizeof(*pAgentEvent));

    IntAlertFillLixProcess(Task, &pAgentEvent->CurrentProcess);

    pAgentEvent->ErrorCode = 0;

    pAgentEvent->Event = Created ? agentStarted : agentTerminated;
    pAgentEvent->AgentTag = Task->AgentTag;
    pAgentEvent->ErrorCode = ExitCode;

    status = IntNotifyIntroEvent(introEventAgentEvent, pAgentEvent, sizeof(*pAgentEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


INTSTATUS
IntLixTaskGetUserStack(
    _In_ LIX_TASK_OBJECT *Task,
    _Out_opt_ QWORD *StackPointer,
    _Out_opt_ QWORD *StackBase,
    _Out_opt_ QWORD *StackLimit
    )
///
/// @brief Finds the user mode stack limits for a Linux process.
///
/// @param[in]  Task         The Linux process.
/// @param[out] StackPointer Will contain, upon successful return, the user mode RSP value.
/// @param[out] StackBase    Will contain, upon successful return, the user mode stack base.
/// @param[out] StackLimit   Will contain, upon successful return, the user mode stack limit.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIX_TRAP_FRAME trapFrame;
    QWORD base, limit;

    status = IntLixTaskGetTrapFrame(Task, &trapFrame);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskGetTrapFrame failed: %08x\n", status);
        return status;
    }

    if (NULL != StackBase || NULL != StackLimit)
    {
        status = IntLixMmFindVmaRange(trapFrame.Rsp, Task, &limit, &base);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to find stack limits for process %s (%d 0x%llx), rsp: 0x%llx. Status:0x%08x\n",
                  Task->Comm, Task->Pid, Task->Gva, trapFrame.Rsp, status);
            return status;
        }

        if (NULL != StackBase)
        {
            *StackBase = base;
        }

        if (NULL != StackLimit)
        {
            *StackLimit = limit;
        }
    }

    if (NULL != StackPointer)
    {
        *StackPointer = trapFrame.Rsp;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskCreate(
    _In_ LIX_TASK_OBJECT *Parent,
    _In_ LIX_TASK_OBJECT *RealParent,
    _In_ QWORD TaskStruct,
    _In_ BOOLEAN StaticDetected,
    _Out_opt_ LIX_TASK_OBJECT **Task
    )
///
/// @brief Creates a Linux process object.
///
/// NOTE: This may return INT_STATUS_NOT_NEEDED_HINT which is a success status but no task object will be
/// created so be careful when using pTask.
///
/// @param[in]  Parent          The parent of the Linux process.
/// @param[in]  RealParent      The real parent of the Linux process.
/// @param[in]  TaskStruct      The guest virtual address of the "task_struct" structure with the process.
/// @param[in]  StaticDetected  TRUE if the process was detected statically.
/// @param[out] Task            Will contain, upon successful return, the newly created task object.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If the process is dying.
/// @returns #INT_STATUS_INSUFFICIENT_RESOURCES If there is not enough memory available.
///
{
    INTSTATUS status;
    LIX_TASK_OBJECT *pTask, *pActualParent;
    DWORD flags = 0;
    QWORD file = 0;

    status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Flags), sizeof(flags), &flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the flags in task 0x%016llx: 0x%08x\n", TaskStruct, status);
        return status;
    }

    if ((flags & PF_EXITING) != 0)
    {
        TRACE("[INFO] Task with 0x%llx is dying while initializing (static: %d)... Will ignore.\n",
              TaskStruct, StaticDetected);
        if (NULL != Task)
        {
            *Task = NULL;
        }
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pTask = HpAllocWithTag(sizeof(*pTask), IC_TAG_POBJ);
    if (NULL == pTask)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pTask->Gva = TaskStruct;

    status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Pid), sizeof(pTask->Pid), &pTask->Pid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the 'PID' in task 0x%016llx: 0x%08x\n", pTask->Gva, status);
        goto _free_and_exit;
    }

    if (!StaticDetected)
    {
        LIX_TASK_OBJECT *pExistingTask = IntLixTaskFindByPid(pTask->Pid);
        if (pExistingTask)
        {
            //
            // For now, just log an error, this is a cache issue 99.999%
            //
            ERROR("[ERROR] [CRITICAL] There is already an existing task with PID %d\n", pTask->Pid);

            LOG("[ERROR] %s%s %s (%d/%d, %16llx)]\n",
                pExistingTask->IsThread ? "Thread" : "Process",
                pExistingTask->KernelMode ? "(KM)" : "",
                pExistingTask->ProcName,
                pExistingTask->Pid, pExistingTask->Tgid, pExistingTask->Gva);
        }
    }

    status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Tgid), sizeof(pTask->Tgid), &pTask->Tgid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the 'tgid' in task 0x%016llx: 0x%08x\n", pTask->Gva, status);
        goto _free_and_exit;
    }

    /// NOTE: We should hook the comm field if we want an fully accurate name for threads
    status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Comm), sizeof(pTask->Comm), pTask->Comm);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading 'comm' in task 0x%016llx: 0x%08x\n", pTask->Gva, status);
        goto _free_and_exit;
    }

    pTask->CommHash = Crc32String(pTask->Comm, INITIAL_CRC_VALUE);

    pTask->IsThread = pTask->Tgid != pTask->Pid;

    if (flags & PF_KTHREAD)
    {
        pTask->IsThread = TRUE;
        pTask->KernelMode = TRUE;
    }

    if (StaticDetected && !pTask->KernelMode)
    {
        // The actual way to determine if a thread was already executed (PF_FORKNOEXEC).
        // But there is another special case:
        // 1. exec /usr/bin/squid (new PID = 32)
        // 2. squid does a fork() (new PID = 33)
        // 3. original squid (PID 32) dies
        //    the parent of squid (PID 33) becomes PID 1
        //    but this should be considered an exec by us
        if (!(flags & PF_FORKNOEXEC) ||
            (!pTask->IsThread && RealParent->Pid == 1))
        {
            pTask->IsThread = FALSE;
            pTask->Exec = TRUE;
        }
    }

    // When activating protection, we care about the TGID, since that's the CR3
    // NOTE: in case this changes in future versions, then get the CR3 and search by that
    pActualParent = RealParent;
    if (!pTask->KernelMode && pTask->IsThread && RealParent->Pid != pTask->Tgid)
    {
        pActualParent = IntLixTaskFindByPid(pTask->Tgid);
        if (NULL == pActualParent)
        {
            WARNING("[WARNING] Task with TGID %d is dead\n", pTask->Tgid);
            pActualParent = RealParent;
        }
    }

    pTask->ActualParent = pActualParent->Gva;
    pTask->RealParent = RealParent->Gva;
    pTask->Parent = Parent->Gva;

    if (gGuest.OSVersion < LIX_CREATE_VERSION(3, 17, 0))
    {
        QWORD time[2] = {0};

        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, StartTime), sizeof(time), time);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the start time in task 0x%016llx: 0x%08x\n", pTask->Gva, status);
            goto _free_and_exit;
        }

        // Convert to nanoseconds
        pTask->CreationTime = time[0] * NSEC_PER_SEC + time[1];
    }
    else
    {
        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, StartTime),
                                sizeof(pTask->CreationTime),
                                &pTask->CreationTime);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the start time in task 0x%016llx: 0x%08x\n", pTask->Gva, status);
            goto _free_and_exit;
        }
    }

    // Forked processes should not have their own memory allocated for the path (if
    // you want a path, get the from the parent). Also, that helps us in no way, since we
    // protect every sub-process (at least until it's doing an exec).
    pTask->StaticDetected = StaticDetected;

    status = IntLixTaskFetchMm(0, pTask, pTask->IsThread ? pActualParent : NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskFetchMm failed: 0x%08x. This task (%s) cannot be protected!\n",
              status, pTask->Comm);
    }

    if (pTask->IsThread || !pTask->StaticDetected || !IS_KERNEL_POINTER_LIX(pTask->MmGva))
    {
        // 1. If we have a thread, it's simple => just inherit the parent name
        // 2. If the process is not found at a static scan => we already got the filename for the task, no
        // point in doing it again
        // 3. An error occurred and we have no mm => nothing we can, so inherit parent
        pTask->ExeFileDentry = pActualParent->ExeFileDentry;

        pTask->Path = IntLixTaskPathGetRef(pActualParent->Path);
    }
    else
    {
        status = IntKernVirtMemFetchQword(pTask->MmGva + LIX_FIELD(MmStruct, ExeFile), &file);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: %08x\n",
                  pTask->MmGva + LIX_FIELD(MmStruct, ExeFile), status);
            goto _initialize_and_prot;
        }

        status = IntLixFileGetDentry(file, &pTask->ExeFileDentry);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixFileGetDentry failed for %llx: %08x\n", file, status);
            goto _initialize_and_prot;
        }

        pTask->Path = IntLixTaskPathGetByDentry(file, 0, pTask->ExeFileDentry);
    }

_initialize_and_prot:

    InitializeListHead(&pTask->Vmas);
    InitializeListHead(&pTask->ExploitProtProcLink);

    InsertTailList(&gLixTasks, &pTask->Link);

    IntLixTaskSetProcName(pTask);

    if (StaticDetected)
    {
        pTask->IsPreviousAgent = pTask->Comm[14] == '?';
    }

    status = IntLixTaskActivateProtection(pTask, pActualParent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskActivateProtection failed for %s (%llx): 0x%08x\n", pTask->Comm, pTask->Gva, status);

        IntLixTaskDeactivateProtection(pTask);
    }

    if (!pTask->KernelMode)
    {
        QWORD creds;

        // On static detected processes, use the real_cred pointer. We may catch the creds inside a
        // override_creds - revert_creds flow, and the creds won't be reliable.
        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Cred), sizeof(creds), &creds);
        if (INT_SUCCESS(status))
        {
            status = IntLixCredAdd(creds, &pTask->Creds);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixCredAdd failed for task %s (%d 0x%llx) with status: 0x%08x!. Creds gva: 0x%llx\n",
                      pTask->Comm, pTask->Pid, pTask->Gva, status, creds);
            }
        }
        else
        {
            ERROR("[ERROR] _IntLixTaskRead failed for task %s (%d 0x%llx): 0x%08x\n",
                  pTask->Comm, pTask->Pid, pTask->Gva, status);
        }

        pTask->UserStack.Valid = TRUE;

        status = IntLixTaskGetUserStack(pTask, NULL, &pTask->UserStack.Base, &pTask->UserStack.Limit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to get user mode stack for process %s (%d, 0x%llx). Status: 0x%08x\n",
                  pTask->Comm, pTask->Pid, pTask->Gva, status);

            pTask->UserStack.Valid = FALSE;
        }
    }

    pTask->Dpi.StolenTokens = RealParent->Dpi.StolenTokens || Parent->Dpi.StolenTokens;

    if (IntLixTaskMustLog(pTask, pTask->Protected != 0))
    {
        if (!pTask->IsThread)
        {
            LOG("[%s]%s %s (%s), (%d/%d, %llx, %llx) [from %s%s %s (%d, %16llx)]\n",
                pTask->Exec ? "EXEC" : "FORK",
                pTask->Protected ? "[PROT]" : "",
                pTask->ProcName,
                pTask->Comm,
                pTask->Pid, pTask->Tgid,
                pTask->Cr3, pTask->Gva,
                pActualParent->IsThread ? "Thread" : "Process",
                pActualParent->KernelMode ? "(KM)" : "",
                pActualParent->ProcName,
                pActualParent->Pid, pActualParent->Gva);
        }
        else
        {
            LOG("[THREAD]%s %s, (%d/%d, %llx, %llx)\n",
                pTask->Protected ? "[PROT]" : "",
                pTask->Comm,
                pTask->Pid, pTask->Tgid,
                pTask->Cr3, pTask->Gva);
        }
    }

    if (pActualParent->AgentTag)
    {
        // Mark this one as agent too
        pTask->AgentTag = IntLixAgentIncProcRef(pTask->Comm);
    }

    if (StaticDetected && pTask->Exec)
    {
        if (NULL == gLixGuest->InitProcessObj && pTask->Pid == 1)
        {
            gLixGuest->InitProcessObj = pTask;
        }

        IntLixTaskSendTaskEvent(pTask, 0, TRUE, FALSE, StaticDetected);
    }

    if (NULL != Task)
    {
        *Task = pTask;
    }

    return INT_STATUS_SUCCESS;

_free_and_exit:
    if (NULL != pTask)
    {
        HpFreeAndNullWithTag(&pTask, IC_TAG_POBJ);
    }

    return status;
}


static void
IntLixTaskRemoveEntry(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Removes a Linux process from the process list.
///
/// @param[in] Task The Linux process.
///
{
    if (Task->Protected)
    {
        IntLixTaskDeactivateProtection(Task);
    }

    IntLixCredRemove(&Task->Creds);

    IntLixTaskPathFree(&Task->Path);

    if (NULL != Task->Interpreter)
    {
        HpFreeAndNullWithTag(&Task->Interpreter, IC_TAG_NAME);
    }

    if (NULL != Task->CmdLine)
    {
        HpFreeAndNullWithTag(&Task->CmdLine, IC_TAG_PCMD);
    }

    HpFreeAndNullWithTag(&Task, IC_TAG_POBJ);
}


static void
IntLixTaskMarkAgent(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Marks a Linux process as being an Introcore agent.
///
/// @param[in] Task The Linux process.
///
{
    INTSTATUS status;
    char specialChar = '?';

    if (!Task->AgentTag || gGuest.ShutDown)
    {
        return;
    }

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                 Task->Gva + LIX_FIELD(TaskStruct, Comm) + 14,
                                 1,
                                 &specialChar,
                                 IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed for task %llx: 0x%08x\n", Task->Gva, status);
    }
}


static void
IntLixTaskDestroy(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ DWORD ExitCode
    )
///
/// @brief Destroys a Linux process after protection for it is removed.
///
/// @param[in] Task The Linux process.
/// @param[in] ExitCode Process exit code.
///
{
    INTSTATUS status;
    DWORD signal;
    BOOLEAN crashed = FALSE, lastAgent = FALSE, wasProtected = FALSE;

    if (Task->Protected)
    {
        IntLixTaskDeactivateProtection(Task);
        wasProtected = TRUE;
    }

    signal = ExitCode & 0x7f;

    if ((ExitCode & 0x80) ||
        signal == SIGQUIT ||
        signal == SIGILL ||
        signal == SIGTRAP ||
        signal == SIGABRT ||
        signal == SIGBUS ||
        signal == SIGFPE ||
        signal == SIGSEGV)
    {
        IntLixTaskSendExceptionEvent(signal, Task);

        crashed = TRUE;
    }

    if (__unlikely(Task->MustKill && signal != SIGKILL))
    {
        WARNING("[WARNING] Task %s (%d, %llx, %llx) was marked to be killed, but the signal it received is %d",
                Task->ProcName, Task->Pid, Task->Cr3, Task->Gva, signal);
    }

    Task->AgentTag = IntLixAgentDecProcRef(Task->Comm, &lastAgent);

    if (Task->Exec)
    {
        IntLixTaskSendTaskEvent(Task, ExitCode, FALSE, crashed, FALSE);
    }

    if (lastAgent)
    {
        IntLixTaskSendAgentEvent(Task, ExitCode, FALSE);
    }

    RemoveEntryList(&Task->Link);

    if (!Task->IsThread && !Task->KernelMode && Task->Cr3 != 0)
    {
        // Invalidate all the entries inside the ICACHE associated to this process.
        status = IntIcFlushVaSpace(gGuest.InstructionCache, Task->Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcFlushVaSpace failed: 0x%08x\n", status);
        }
    }

    // One last check on process exit

    IntLixCredsVerify(Task);

    IntLixCredRemove(&Task->Creds);

    if (IntLixTaskMustLog(Task, wasProtected))
    {
        LOG("[EXIT] %s %s (%d, %llx, %llx), crashed: %d, signal: %d\n",
            Task->IsThread ? "Thread" : "Process", Task->ProcName, Task->Pid,
            Task->Cr3, Task->Gva, crashed, signal);
    }

    if (!Task->IsThread)
    {
        IntUDRemoveAllEntriesForCr3(Task->Cr3);
    }

    IntLixTaskRemoveEntry(Task);
}


__forceinline
static DWORD
IntLixTaskGetDpiMitreId(
    _In_ DWORD Flags
    )
///
/// @brief Returns the MITRE ID for the process creation violation flag.
///
/// @param[in] Flags The DPI violation flags.
///
/// @returns The MITRE ID for the specified DPI violation flags.
///
{
    if (INT_PC_VIOLATION_DPI_STOLEN_TOKEN & Flags)
    {
        return idAccessToken;
    }

    if (INT_PC_VIOLATION_DPI_PIVOTED_STACK & Flags)
    {
        return idExploitClientExec;
    }

    ERROR("[ERROR] We do not have any known DPI flag set -> Flags:0x%x\n", Flags);
    return 0;
}


static void
IntLixTaskSendBlockedEvent(
    _In_ LIX_TASK_OBJECT *OldTask,
    _In_ LIX_TASK_OBJECT *NewTask,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ DWORD PcType
    )
///
/// @brief Sends a blocked process creation event.
///
/// @param[in] OldTask The process that attempted to spawn the NewTask.
/// @param[in] NewTask The process that tried to be spawned by the OldTask.
/// @param[in] Action  The action that was taken.
/// @param[in] Reason  The reason the action was taken.
/// @param[in] PcType  The process creation violation type.
///
{
    INTSTATUS status;
    EVENT_PROCESS_CREATION_VIOLATION *pEvent;

    pEvent = &gAlert.ProcessCreation;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = Action;
    pEvent->Header.Reason = Reason;
    pEvent->Header.MitreID = idExecApi;

    pEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_PREVENT_CHILD_CREATION, OldTask, Reason, 0);

    // Fill with OldTask info, since that is the current process (it's more relevant this way)
    IntAlertFillLixProcess(OldTask, &pEvent->Header.CurrentProcess);

    IntAlertFillCpuContext(TRUE, &pEvent->Header.CpuContext);
    IntAlertFillVersionInfo(&pEvent->Header);

    IntAlertFillLixProcess(NewTask, &pEvent->Originator);
    IntAlertFillLixProcess(OldTask, &pEvent->Victim);

    if (PcType)
    {
        pEvent->PcType = PcType;
        pEvent->Header.MitreID = IntLixTaskGetDpiMitreId(PcType);
    }

    status = IntNotifyIntroEvent(introEventProcessCreationViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


__forceinline
static DWORD
IntLixTaskGetDpiViolationFlags(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Returns the DPI flags for a Linux process.
///
/// @param[in] Task The Linux process.
///
/// @returns A combination of process creation violation flags.
///
{
    DWORD flags = 0;

    if (Task->Dpi.IsPivoted)
    {
        flags |= INT_PC_VIOLATION_DPI_PIVOTED_STACK;
    }

    if (Task->Dpi.StolenTokens)
    {
        flags |= INT_PC_VIOLATION_DPI_STOLEN_TOKEN;
    }

    return flags;
}


static void
IntLixValidateProcessCreationRights(
    _In_ LIX_TASK_OBJECT *ChildTask,
    _In_ LIX_TASK_OBJECT *ParentTask,
    _In_ INTRO_OBJECT_TYPE ObjectType,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief Validates process creation rights (both PC and DPI).
///
/// @param[in]  ChildTask  The process whose creation this function will check.
/// @param[in]  ParentTask The process that attempted to spawn the child process. (via exec() system call)
/// @param[in]  ObjectType The rights that this function should validate. (One of #introObjectTypeProcessCreation or
///                        #introObjectTypeProcessCreationDpi)
/// @param[out] Action     The action that must be taken.
/// @param[out] Reason     The reason for the action.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };

    *Action = introGuestAllowed;
    *Reason = introReasonAllowed;

    if (ObjectType != introObjectTypeProcessCreation && ObjectType != introObjectTypeProcessCreationDpi)
    {
        ERROR("[ERROR] IntLixValidateProcessCreationRights called with object type %d!\n", ObjectType);
        return;
    }

    // If the process re-executes to self, then we'll allow it
    if (ChildTask->ReExecToSelf)
    {
        return;
    }

    // Ignore kthreads
    if (ParentTask->KernelMode)
    {
        return;
    }

    if (ObjectType == introObjectTypeProcessCreationDpi)
    {
        originator.PcType = IntLixTaskGetDpiViolationFlags(ChildTask);

        if (originator.PcType == 0)
        {
            *Action = introGuestAllowed;
            *Reason = introReasonAllowed;

            return;
        }
    }

    status = IntExceptUserGetOriginator(ChildTask, FALSE, 0, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptUserGetOriginator failed with status: 0x%08x.\n", status);
        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;
        return;
    }

    status = IntExceptGetVictimProcessCreation(ParentTask, ObjectType, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimProcessCreation failed with status: 0x%08x.\n", status);
        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;
        return;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, Action, Reason, introEventProcessCreationViolation);

    if (ObjectType == introObjectTypeProcessCreation)
    {
        if (IntPolicyProcTakeAction(PROC_OPT_PROT_PREVENT_CHILD_CREATION, ParentTask, Action, Reason))
        {
            LOG("[PROCESS CREATION] Process creation blocked. Process `%s` tried to start using process `%s`",
                ChildTask->Comm, ParentTask->Comm);

            IntLixTaskSendBlockedEvent(ParentTask, ChildTask, *Action, *Reason, originator.PcType);

            IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_PREVENT_CHILD_CREATION, ParentTask, Action);
        }
    }
    else
    {
        if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_DPI, Action, Reason))
        {
            LOG("[PROCESS CREATION] Process creation blocked. Process `%s` tried to start with DPI using process `%s`",
                ChildTask->Comm, ParentTask->Comm);

            IntLixTaskSendBlockedEvent(ParentTask, ChildTask, *Action, *Reason, originator.PcType);

            IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_DPI, Action);
        }
    }
}


INTSTATUS
IntLixTaskIsUserStackPivoted(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Ptr,
    _Out_ BOOLEAN *IsPivoted
    )
///
/// @brief Verifies whether the stack of a Linux process is pivoted or not.
///
/// @param[in] Task The Linux process.
/// @param[in] Ptr The current RSP value.
/// @param[out] IsPivoted Upon successful return, will be set to TRUE if the stack is pivoted, FALSE otherwise.
///
/// @returns #INT_STATUS_SUCCESS             On success.
/// @returns #INT_STATUS_INVALID_PARAMETER_1 If the Task parameter does not point to a valid memory location or the
///                                          process is a kernel thread.
/// @returns #INT_STATUS_INVALID_PARAMETER_2 If the Ptr parameter is a kernel pointer.
/// @returns #INT_STATUS_INVALID_PARAMETER_3 If IsPivoted parameter does not point to a valid memory location.
///
{
    INTSTATUS status;
    QWORD base, limit;

    if (NULL == Task || Task->KernelMode)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (IS_KERNEL_POINTER_LIX(Ptr))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == IsPivoted)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Task->UserStack.Valid)
    {
        if (__likely(IN_RANGE_INCLUSIVE(Ptr, Task->UserStack.Limit, Task->UserStack.Base)))
        {
            *IsPivoted = FALSE;

            return INT_STATUS_SUCCESS;
        }
    }

    if (!Task->IsThread)
    {
        if (__unlikely(0 == Task->MmGva))
        {
            WARNING("[WARNING] Parent task %s (%d 0x%llx) is not a thread and doesn't have a valid mm pointer!\n",
                    Task->Comm, Task->Pid, Task->Gva);

            goto _check_altstack;
        }

        status =  IntKernVirtMemFetchQword(Task->MmGva + LIX_FIELD(MmStruct, StartStack), &base);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to read start_stack from mm. Task %s (%d 0x%llx), MmGva 0x%llx, status: 0x%08x\n",
                  Task->Comm, Task->Pid, Task->Gva, Task->MmGva, status);
            return status;
        }

        status = IntLixMmFindVmaRange(base, Task, &limit, &base);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to find VAD for task->mm.start_stack(0x%llx) for process %s (%d 0x%llx). "
                  "Status: 0x%08x\\n", base, Task->Comm, Task->Pid, Task->Gva, status);
            return status;
        }

        if (__likely(IN_RANGE_INCLUSIVE(Ptr, limit, base)))
        {
            *IsPivoted = FALSE;
            return INT_STATUS_SUCCESS;
        }
    }

_check_altstack:
    status = IntKernVirtMemFetchQword(Task->Gva + LIX_FIELD(TaskStruct, AltStackSp), &base);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read alt stack. Task %s (%d 0x%llx), status: 0x%08x\n",
              Task->Comm, Task->Pid, Task->Gva, status);

        return status;
    }

    if (0 != base)
    {
        status = IntLixMmFindVmaRange(base, Task, &limit, &base);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to find alt stack (0x%llx) VAD for process %s (%d 0x%llx). Status: 0x%08x\n",
                  base, Task->Comm, Task->Pid, Task->Gva, status);
            return status;
        }

        if (IN_RANGE_INCLUSIVE(Ptr, limit, base))
        {
            *IsPivoted = FALSE;
            return INT_STATUS_SUCCESS;
        }
    }

    // NOTE: Should we set this right after the check_altstack label?
    *IsPivoted = TRUE;

    return INT_STATUS_SUCCESS;
}


static void
IntLixValidateExecStack(
    _In_ LIX_TASK_OBJECT *ParentTask,
    _In_ LIX_TASK_OBJECT *CurrentTask
    )
///
/// @brief Validates the user mode stack of a process upon an exec() system call.
///
/// @param[in] ParentTask  The process that performed the exec().
/// @param[in] CurrentTask The process that follows to be spawned.
///
{
    INTSTATUS status;

    QWORD stackPointer;

    if (ParentTask->KernelMode)
    {
        return;
    }

    status = IntLixTaskGetUserStack(ParentTask, &stackPointer, NULL, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to get user mode stack pointer for parent task %s (%d 0x%llx). Status: 0x%08x\n",
              ParentTask->Comm, ParentTask->Pid, ParentTask->Gva, status);
        return;
    }

    status = IntLixTaskIsUserStackPivoted(ParentTask, stackPointer, &CurrentTask->Dpi.IsPivoted);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskIsStackPivoted failed for stack ptr 0x%llx with status 0x%08x.", stackPointer, status);
    }
}


INTSTATUS
IntLixTaskHandleExec(
    _In_ void *Detour
    )
///
/// @brief Handles the exec() system call of a linux process.
///
/// @param[in] Detour Unused.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_INVALID_INTERNAL_STATE If the process that is currently performing the exec() cannot be found.
/// @returns #INT_STATUS_INSUFFICIENT_RESOURCES If there is not enough memory available.
{
    INTSTATUS status;
    QWORD binprm, dPathResult;
    BOOLEAN lastAgent;
    LIX_TASK_OBJECT *pTask;
    LIX_TASK_OBJECT *pOldTask;
    INTRO_ACTION action = introGuestAllowed;
    INTRO_ACTION_REASON reason = introReasonAllowed;
    QWORD oldProtectionMask;
    static DWORD taskCount = 0;

    UNREFERENCED_PARAMETER(Detour);

    pOldTask = IntLixTaskFindByGva(gVcpu->Regs.R8);
    if (NULL == pOldTask)
    {
        ERROR("[ERROR] No task on for exec!\n");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    lastAgent = FALSE;
    binprm = gVcpu->Regs.R9;
    dPathResult = gVcpu->Regs.R10;

    // Keep the old protection mask in order to validate the process creation rights
    oldProtectionMask = pOldTask->Protection.Mask;

    // It's certain that the CR3 will change, so disable the protection (doing a full cleanup).
    // It will be activated again after we get the new CR3 (if it's still a protected process)
    IntLixTaskDeactivateProtection(pOldTask);

    // no point in keeping it anymore
    pOldTask->IsPreviousAgent = FALSE;

    pTask = HpAllocWithTag(sizeof(LIX_TASK_OBJECT), IC_TAG_POBJ);
    if (NULL == pTask)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntLixTaskCreateFromBinprm(pOldTask, binprm, dPathResult, pTask);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed updating process contents from the linux_binprm @ %16llx: 0x%08x\n",
              binprm, status);
        // Add it to the list, still...
    }

    // Only now set the comm to whatever we have. Let's hope the #IntLixTaskUpdateFromBinprm didn't fail to
    // read the name/path. In that case, there is nothing we can do.
    if (pTask->Path)
    {
        strlcpy(pTask->Comm, pTask->Path->Name, sizeof(pTask->Comm));

        pTask->CommHash = Crc32String(pTask->Comm, INITIAL_CRC_VALUE);
    }
    else
    {
        ERROR("[ERROR] We couldn't get path for process, the comm will be the old one!\n");
    }

    // Only update here! We check this flag when we update from the binprm.
    pTask->Exec = TRUE;

    // Check if this is the init process, and save the new pointer to it.
    if (__unlikely((NULL == gLixGuest->InitProcessObj && pTask->Pid == 1) ||
                   gLixGuest->InitProcessObj == pOldTask))
    {
        if (gLixGuest->InitProcessObj == pOldTask)
        {
            TRACE("[INIT] Init process re-executes itself\n");
        }

        gLixGuest->InitProcessObj = pTask;
    }

    IntLixCredsVerify(pOldTask);

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_STACK_PIVOT)
    {
        IntLixValidateExecStack(pOldTask, pTask);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI)
    {
        IntLixValidateProcessCreationRights(pTask, pOldTask, introObjectTypeProcessCreationDpi, &action, &reason);

        if (action == introGuestNotAllowed)
        {
            goto _action_not_allowed;
        }
    }

    if (oldProtectionMask & PROC_OPT_PROT_PREVENT_CHILD_CREATION)
    {
        IntLixValidateProcessCreationRights(pTask, pOldTask, introObjectTypeProcessCreation, &action, &reason);
    }

_action_not_allowed:
    if (action == introGuestNotAllowed)
    {
        status = IntDetSetReturnValue(Detour, &gVcpu->Regs, (QWORD) - EACCES);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetSetReturnValue failed: %08x\n", status);
        }

        IntLixTaskRemoveEntry(pTask);

        return INT_STATUS_SUCCESS;
    }


    InsertAfterList(&pOldTask->Link, &pTask->Link);
    RemoveEntryList(&pOldTask->Link);

    // Now it's safe to reactivate the protection. The new CR3 is in place.
    // We also don't depend on the parent anymore.
    status = IntLixTaskActivateProtection(pTask, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskActivateProtection failed for %s: 0x%08x\n", pTask->Comm, status);

        IntLixTaskDeactivateProtection(pTask);

        pTask->Protected = FALSE;
    }

    if (pTask->Protection.Mask & PROC_OPT_PROT_SCAN_CMD_LINE)
    {
        status = IntLixTaskFetchCmdLine(pTask, binprm);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskFetchCmdLine failed with status: 0%08x\n", status);
        }
        else
        {
            status = IntLixCmdLineInspect(pTask);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixCmdLineInspect failed with status: 0%08x\n", status);
            }
        }
    }

    if (IntLixTaskMustLog(pTask, pTask->Protected != 0))
    {
        if (pTask->Interpreter != NULL)
        {
            LOG("[EXEC] %s %s (%d, %llx, %llx) exec to %s (interp: %s)\n",
                pOldTask->IsThread ? "Thread" : "Process", pOldTask->Comm, pTask->Pid, pTask->Cr3, pTask->Gva,
                pTask->ProcName, pTask->Interpreter);
        }
        else
        {
            LOG("[EXEC] %s %s (%d, %llx, %llx) exec to %s\n",
                pOldTask->IsThread ? "Thread" : "Process", pOldTask->Comm, pTask->Pid, pTask->Cr3,
                pTask->Gva, pTask->ProcName);
        }

        if (pTask->CmdLine)
        {
            LOG("[EXEC] Task '%s' has command line '%s'\n", pTask->ProcName, pTask->CmdLine);
        }
    }

    if (pOldTask->AgentTag)
    {
        size_t oldLen = strlen_s(pTask->Comm, sizeof(pTask->Comm));
        size_t newLen = strlen_s(pOldTask->Comm, sizeof(pOldTask->Comm));

        // If it changed the name, then we need to decrement the old agent refcount
        // If it didn't change the name, then we must leave it marked as agent (and don't decrement!)
        if ((oldLen != newLen) || (0 != memcmp(pOldTask->Comm, pTask->Comm, oldLen)))
        {
            pTask->AgentTag = IntLixAgentDecProcRef(pOldTask->Comm, &lastAgent);
        }
    }
    else
    {
        // What if it executed to a new agent !? Simple, we mark this as an agent too...
        pTask->AgentTag = IntLixAgentIncProcRef(pTask->Comm);
    }

    if (lastAgent)
    {
        IntLixTaskSendAgentEvent(pTask, 0, FALSE);
    }
    else if (!pOldTask->AgentTag && pTask->AgentTag)
    {
        IntLixTaskSendAgentEvent(pTask, 0, TRUE);
    }

    IntLixTaskSendTaskEvent(pTask, 0, TRUE, FALSE, FALSE);

    IntLixTaskRemoveEntry(pOldTask);

    if (taskCount == 1)
    {
        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_VDSO)
        {
            status = IntLixVdsoDynamicProtect();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixVdsoDynamicProtect failed with status: 0x%08x.", status);
            }
        }
    }
    taskCount++;

    status = IntDetSetReturnValue(Detour, &gVcpu->Regs, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: %08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskHandleFork(
    _In_ void *Detour
    )
///
/// @brief Handles the fork() system call performed by a linux process.
///
/// @param[in] Detour Unused.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Detour);

    INTSTATUS status = IntLixTaskAdd(gVcpu->Regs.R9, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskAdd failed for %llx on cpu %d: 0x%08x\n",
              gVcpu->Regs.R9, gVcpu->Index, status);
    }

    return INT_STATUS_SUCCESS;
}


static void
IntLixTaskSendInjectionEvent(
    _In_ LIX_TASK_OBJECT *Source,
    _In_ LIX_TASK_OBJECT *Victim,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an injection event.
///
/// @param[in] Source The Linux process that tried to perform the injection.
/// @param[in] Victim The Linux process that was the victim of the injection.
/// @param[in] Action The action that was taken.
/// @param[in] Reason The reason for the action.
///
{
    INTSTATUS status;
    EVENT_MEMCOPY_VIOLATION *pInjEvent;

    pInjEvent = &gAlert.Injection;

    memzero(pInjEvent, sizeof(*pInjEvent));

    pInjEvent->Header.Action = Action;
    pInjEvent->Header.Reason = Reason;
    pInjEvent->Header.MitreID = idProcInject;

    IntAlertFillCpuContext(FALSE, &pInjEvent->Header.CpuContext);

    pInjEvent->DestinationVirtualAddress = 0;
    pInjEvent->SourceVirtualAddress = 0;

    IntAlertFillLixProcess(Source, &pInjEvent->Originator.Process);
    IntAlertFillLixProcess(Victim, &pInjEvent->Victim.Process);

    IntAlertFillLixCurrentProcess(&pInjEvent->Header.CurrentProcess);

    pInjEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_WRITE_MEM, Victim, Reason, 0);

    pInjEvent->Header.Flags |= ALERT_FLAG_LINUX;
    pInjEvent->Header.Flags |= ALERT_FLAG_NOT_RING0;

    IntAlertFillVersionInfo(&pInjEvent->Header);

    status = IntNotifyIntroEvent(introEventInjectionViolation, pInjEvent, sizeof(*pInjEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntLixTaskHandleInjection(
    _In_ QWORD Victim,
    _In_ BOOLEAN Pid,
    _In_ QWORD InjectionFlag,
    _Out_ BOOLEAN *Block
    )
///
/// @brief Handles the injection into a protected process.
///
/// @param[in] Victim The PID or guest virtual address of the victim's "task_struct".
/// @param[in] Pid    If the Victim parameter represents the process PID.
/// @param[in] InjectionFlag The type of the injection.
/// @param[out] Block        Will be set with the action that must be taken. (TRUE means block, FALSE means allow)
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD currentTask;
    LIX_TASK_OBJECT *pSource, *pVictim;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    EXCEPTION_UM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;

    *Block = FALSE;
    pSource = pVictim = NULL;

    status = IntLixTaskGetCurrentTaskStruct(gVcpu->Index, &currentTask);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskGetCurrentStruct failed: 0x%08x\n", status);
        return status;
    }

    for_each_task(pProc)
    {
        if ((Pid && pProc->Pid == (DWORD)Victim) || (!Pid && pProc->Gva == Victim))
        {
            pVictim = pProc;
        }

        if (pProc->Gva == currentTask)
        {
            pSource = pProc;
        }

        if ((NULL != pVictim) && (NULL != pSource))
        {
            break;
        }
    }

    if (NULL == pVictim || NULL == pSource)
    {
        // We don't know these processes
        return INT_STATUS_SUCCESS;
    }

    if (!(pVictim->Protection.Mask & InjectionFlag))
    {
        LOG("[PTRACE] Injection from %s (%d, %llx) into %s (%d, %llx)\n",
            pSource->ProcName, pSource->Pid, pSource->Gva,
            pVictim->ProcName, pVictim->Pid, pVictim->Gva);
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsUser);

    // from now on, block by default
    action = introGuestNotAllowed;
    reason = introReasonUnknown;

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    status = IntExceptUserGetOriginator(pSource, FALSE, 0, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _send_notification;
    }

    status = IntExceptGetVictimProcess(pVictim, 0, 0, ZONE_WRITE, &victim);

    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

_send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_WRITE_MEM, pVictim, &action, &reason))
    {
        LOG("[INJECTION] Block injection from process %s (%d) into process %s (%d)\n",
            pSource->Comm, pSource->Pid, pVictim->Comm, pVictim->Pid);

        IntLixTaskSendInjectionEvent(pSource, pVictim, introGuestNotAllowed, introReasonNoException);
    }
    else
    {
        LOG("[INJECTION] Allow injection from process %s into process %s\n",
            pSource->Comm, pVictim->Comm);
    }


    IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_WRITE_MEM, pVictim, &action);

    *Block = action == introGuestNotAllowed;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskHandleVmRw(
    _In_ void *Detour
    )
///
/// @brief Handles the process_vm_writev() system call.
///
/// This function will deny any foreign memory writes attempted into a protected process.
//
/// Note:Even though the detoured function is "process_vm_rw_core" which handles both reads and writes inside the
/// memory space of another process, this function assumes the code that is detouring this function will filter
/// the actions and will perform the hypercall only when a write is attempted.
///
/// @param[in] Detour Unused.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    BOOLEAN block = FALSE;

    DWORD pid = (DWORD)gVcpu->Regs.R9;

    status = IntLixTaskHandleInjection(pid, TRUE, PROC_OPT_PROT_WRITE_MEM, &block);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskHandleInjection failed: %08x\n", status);
        goto _emulate_and_leave;
    }

_emulate_and_leave:
    status = IntDetSetReturnValue(Detour, &gVcpu->Regs, block ? -EACCES : 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetoursGstSetReturnValue failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskHandlePtrace(
    _In_ void *Detour
    )
///
/// @brief Handles the ptrace() system call.
///
/// This function will deny any ptrace() request that may taint a process which is being protected. The currently
/// handled requests are PTRACE_POKE* and PTRACE_SET*REGS.
///
/// @param[in] Detour Unused.
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    BOOLEAN block = FALSE;

    QWORD child = gVcpu->Regs.R8;
    QWORD request = gVcpu->Regs.R9;

    if (PTRACE_POKEDATA == request || PTRACE_POKETEXT == request)
    {
        status = IntLixTaskHandleInjection(child, FALSE, PROC_OPT_PROT_WRITE_MEM, &block);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskHandleInjection failed: %08x\n", status);
            goto _emulate_and_leave;
        }
    }
    else if (PTRACE_SETFPREGS == request || PTRACE_SETFPXREGS == request || PTRACE_SETREGS == request)
    {
        status = IntLixTaskHandleInjection(child, FALSE, PROC_OPT_PROT_PTRACE, &block);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskHandleSetRegs failed: %08x\n", status);
            goto _emulate_and_leave;
        }
    }
    else
    {
        WARNING("[WARNING] The request argument (%llx) for 'ptrace' is allowed ...\n", request);
        block = FALSE;
        goto _emulate_and_leave;
    }

_emulate_and_leave:

    status = IntDetSetReturnValue(Detour, &gVcpu->Regs, block ? -EACCES : 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetoursGstSetReturnValue failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskHandleDoExit(
    _In_ void *Detour
    )
///
/// @brief Handles the exit() system call.
///
/// @param[in] Detour Unused.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Detour);

    LIX_TASK_OBJECT *pTask = IntLixTaskFindByGva(gVcpu->Regs.R8);
    if (NULL == pTask)
    {
        TRACE("[INFO] Task dying without being in the list... Ignore it!");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (__unlikely(pTask == gLixGuest->InitProcessObj))
    {
        LOG("[ERROR] Init task is exiting, something isn't right...\n");
    }

    IntLixTaskDestroy(pTask, (DWORD)gVcpu->Regs.R9);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskIterateThreadNode(
    _In_ QWORD TaskStructGva,
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Iterates the threads of a Linux process based on the thread node..
///
/// @param[in] TaskStructGva The guest virtual address of the process's "task_struct".
/// @param[in] Callback      The callback that should be called for each thread found.
/// @param[in] Aux           Context that will be sent as a parameter to the provided callback.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT        If the process does not have any other threads.
/// @returns #INT_STATUS_INVALID_OBJECT_TYPE    If any inconsistencies related to the process are found.
/// @returns #INT_STATUS_INVALID_INTERNAL_STATE If an internal error occurred.
///

{
    INTSTATUS status;
    QWORD currentThread;
    QWORD signal = 0;
    QWORD signalListHead = 0;
    int nrThreads = 0;
    DWORD count = 0;

    if (gLixGuest->Version.Version >= 3)
    {
        status = IntKernVirtMemFetchQword(TaskStructGva + LIX_FIELD(TaskStruct, Signal), &signal);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading the signal struct: 0x%08x\n", status);
            return status;
        }

        if (!IS_KERNEL_POINTER_LIX(signal))
        {
            ERROR("[ERROR] task->signal value (0x%llx) does not point to a valid kernel memory location.", signal);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = IntKernVirtMemFetchDword(signal + LIX_FIELD(Ungrouped, SignalNrThreads), (DWORD *)&nrThreads);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading from the signal struct: 0x%08x\n", status);
            return status;
        }

        // We must subtract the entry that's TaskStructGva
        nrThreads--;

        // Only one thread in this signal struct, so skip it
        if (nrThreads == 0)
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
        else if (nrThreads < 0)
        {
            ERROR("[ERROR] Negative number of threads: %d\n", nrThreads);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }
    }

    signalListHead = signal + LIX_FIELD(Ungrouped, SignalListHead);

    status = IntKernVirtMemFetchQword(signalListHead, &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the first task from signal 0x%016llx\n", signalListHead);
        return status;
    }

    currentThread -= LIX_FIELD(TaskStruct, ThreadNode);

    // This one was already added, so skip it and go to the next one
    status = IntKernVirtMemFetchQword(currentThread + LIX_FIELD(TaskStruct, ThreadNode), &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the next task from 0x%016llx\n",
              currentThread + LIX_FIELD(TaskStruct, ThreadNode));
        return status;
    }

    while ((currentThread != signalListHead) && (count++ < LIX_PROCESSES_MAX_COUNT))
    {
        if (!IS_KERNEL_POINTER_LIX(currentThread))
        {
            ERROR("[ERROR] Thread 0x%llx does not point to a valid kernel memory location.\n", currentThread);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        currentThread -= LIX_FIELD(TaskStruct, ThreadNode);

        status = Callback(currentThread, Aux);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
        else if (INT_STATUS_BREAK_ITERATION == status)
        {
            return INT_STATUS_SUCCESS;
        }

        nrThreads--;

        status = IntKernVirtMemFetchQword(currentThread + LIX_FIELD(TaskStruct, ThreadNode), &currentThread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the next task from 0x%016llx\n",
                  currentThread + LIX_FIELD(TaskStruct, ThreadNode));
            break;
        }
    }

    if (gLixGuest->Version.Version >= 3)
    {
        if (nrThreads > 0)
        {
            ERROR("[ERROR] We didn't processed enough threads. Remaining: %d\n", nrThreads);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
        else if (nrThreads < 0)
        {
            ERROR("[ERROR] We processed more threads. Over: %d\n", nrThreads);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskIterateThreadGroup(
    _In_ QWORD TaskStructGva,
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Iterates the threads of a Linux process based on the thread group.
///
/// @param[in] TaskStructGva The guest virtual address of the process's "task_struct".
/// @param[in] Callback      The callback that should be called for each thread found.
/// @param[in] Aux           Context that will be sent as a parameter to the provided callback.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT        If the process does not have any other threads.
/// @returns #INT_STATUS_INVALID_OBJECT_TYPE    If any inconsistencies related to the process are found.
/// @returns #INT_STATUS_INVALID_INTERNAL_STATE If an internal error occurred.
///
{
    INTSTATUS status;
    QWORD currentThread;
    QWORD signal, threadListHead;
    DWORD count = 0;
    int nrThreads = 0;

    if (gLixGuest->Version.Version >= 3)
    {
        status = IntKernVirtMemFetchQword(TaskStructGva + LIX_FIELD(TaskStruct, Signal), &signal);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading the signal struct: 0x%08x\n", status);
            return status;
        }

        if (!IS_KERNEL_POINTER_LIX(signal))
        {
            ERROR("[ERROR] task->signal value (0x%llx) does not point to a valid kernel memory location.", signal);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = IntKernVirtMemFetchDword(signal + LIX_FIELD(Ungrouped, SignalNrThreads), (DWORD *)&nrThreads);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading from the signal struct: 0x%08x\n", status);
            return status;
        }

        // We must subtract the entry that's TaskStructGva
        nrThreads--;

        // Only one thread in this signal struct, so skip it
        if (nrThreads == 0)
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
        else if (nrThreads < 0)
        {
            ERROR("[ERROR] Negative number of threads: %d\n", nrThreads);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }
    }

    threadListHead = TaskStructGva + LIX_FIELD(TaskStruct, ThreadGroup);

    status = IntKernVirtMemFetchQword(threadListHead, &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the first task from signal 0x%016llx\n", threadListHead);
        return status;
    }

    while (currentThread && (currentThread != threadListHead) && (count++ < LIX_PROCESSES_MAX_COUNT))
    {
        if (!IS_KERNEL_POINTER_LIX(currentThread))
        {
            ERROR("[ERROR] Thread 0x%llx does not point to a valid kernel memory location.\n", currentThread);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        currentThread -= LIX_FIELD(TaskStruct, ThreadGroup);

        status = Callback(currentThread, Aux);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
        else if (INT_STATUS_BREAK_ITERATION == status)
        {
            return INT_STATUS_SUCCESS;
        }

        nrThreads--;

        status = IntKernVirtMemFetchQword(currentThread + LIX_FIELD(TaskStruct, ThreadGroup), &currentThread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the next task from 0x%016llx\n",
                  currentThread + LIX_FIELD(TaskStruct, ThreadGroup));
            break;
        }
    }

    if (gLixGuest->Version.Version >= 3)
    {
        if (nrThreads > 0)
        {
            ERROR("[ERROR] We didn't processed enough threads. Remaining: %d\n", nrThreads);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
        else if (nrThreads < 0)
        {
            ERROR("[ERROR] We processed more threads. Over: %d\n", nrThreads);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskIterateThreads(
    _In_ QWORD TaskStructGva,
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Iterates the threads of a Linux process.
///
/// @param[in] TaskStructGva The guest virtual address of the process's "task_struct".
/// @param[in] Callback      The callback that should be called for each thread found.
/// @param[in] Aux           Context that will be sent as a parameter to the provided callback.
///
/// @returns #INT_STATUS_SUCCESS         On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If the processes from the guest operating system does not have a thread list.
///
{
    if (0 != LIX_FIELD(TaskStruct, ThreadGroup))
    {
        return IntLixTaskIterateThreadGroup(TaskStructGva, Callback, Aux);
    }
    else if (0 != LIX_FIELD(TaskStruct, ThreadNode))
    {
        return IntLixTaskIterateThreadNode(TaskStructGva, Callback, Aux);
    }
    else
    {
        // WARNING("[WARNING] IntLixTaskIterateThreads while not a single process was created!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }
}


INTSTATUS
IntLixTaskIterateGuestTasks(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Iterates the guest process list and calls the provided callback for each process and thread found.
///
/// @param[in] Callback The callback that should be called for each task.
/// @param[in] Aux      Context that will be sent as a parameter to the provided callback.
///
/// @returns #INT_STATUS_SUCCESS       On success.
/// @returns #INT_STATUS_NOT_SUPPORTED If the number of processes found exceeds the internal limit.
///
{
    INTSTATUS status;
    QWORD initGva, currentTask;
    DWORD count = 0;

    status = IntLixGetInitTask(&initGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed finding the init_task: 0x%08x\n", status);
        return status;
    }

    //
    // IMPORTANT: We must call the callback for the init_task too!
    //
    status = Callback(initGva, Aux);
    if (!INT_SUCCESS(status))
    {
        return status;
    }
    else if (INT_STATUS_BREAK_ITERATION == status)
    {
        return INT_STATUS_SUCCESS;
    }

    status = IntLixTaskIterateThreads(initGva, Callback, Aux);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntKernVirtMemFetchQword(initGva + LIX_FIELD(TaskStruct, Tasks), &currentTask);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the first task from 0x%016llx\n", initGva + LIX_FIELD(TaskStruct, Tasks));
        return status;
    }

    currentTask -= LIX_FIELD(TaskStruct, Tasks);

    while (currentTask != initGva && (count++ < LIX_PROCESSES_MAX_COUNT))
    {
        if (!IS_KERNEL_POINTER_LIX(currentTask))
        {
            ERROR("[ERROR] task_struct 0x%llx does not point to a valid kernel memory location.\n", currentTask);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = Callback(currentTask, Aux);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
        else if (INT_STATUS_BREAK_ITERATION == status)
        {
            return INT_STATUS_SUCCESS;
        }

        IntLixTaskIterateThreads(currentTask, Callback, Aux);

        status = IntKernVirtMemFetchQword(currentTask + LIX_FIELD(TaskStruct, Tasks), &currentTask);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the next task from 0x%016llx\n",
                  currentTask + LIX_FIELD(TaskStruct, Tasks));
            break;
        }

        currentTask -= LIX_FIELD(TaskStruct, Tasks);
    }

    if (count >= LIX_PROCESSES_MAX_COUNT)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskCreateInitTask(
    _In_ QWORD TaskGva,
    _Out_opt_ LIX_TASK_OBJECT **Task
    )
///
/// @brief Creates the init task object.
///
/// @param[in]  TaskGva The guest virtual address of the init task.
/// @param[out] Task    Will contain, upon successful return, a reference to the newly created task.
///
/// @returns #INT_STATUS_SUCCESS                 On success.
/// @returns #INT_STATUS_INSUFFICIENT_RESOURCES  If there is not enough available memory.
///
{
    INTSTATUS status;
    LIX_TASK_OBJECT *pInitTask;

    pInitTask = HpAllocWithTag(sizeof(*pInitTask), IC_TAG_POBJ);
    if (NULL == pInitTask)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pInitTask->Gva = TaskGva;
    TRACE("[LIXTASK] Init task @ 0x%016llx\n", pInitTask->Gva);

    // Linux convention...
    pInitTask->Parent = TaskGva;
    pInitTask->RealParent = TaskGva;

    pInitTask->Path = NULL;
    pInitTask->Interpreter = NULL;
    pInitTask->IsThread = TRUE;
    pInitTask->KernelMode = TRUE;
    pInitTask->Protection.Mask = 0;
    pInitTask->Protected = FALSE;
    pInitTask->Context = 0;

    status = IntKernVirtMemFetchDword(pInitTask->Gva + LIX_FIELD(TaskStruct, Pid), &pInitTask->Pid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting PID of the init process @0x%016llx: 0x%08x\n",
              pInitTask->Gva, status);
    }

    status = IntKernVirtMemRead(pInitTask->Gva + LIX_FIELD(TaskStruct, Comm),
                                sizeof(pInitTask->Comm),
                                pInitTask->Comm,
                                NULL);

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading init process name @ 0x%016llx: 0x%08x\n",
              pInitTask->Gva + LIX_FIELD(TaskStruct, Comm), status);
        pInitTask->Comm[0] = 0;
    }

    // Make sure the NULL terminator is there.
    pInitTask->Comm[sizeof(pInitTask->Comm) - 1] = 0;

    pInitTask->CommHash = Crc32String(pInitTask->Comm, INITIAL_CRC_VALUE);

    if ((0 == LIX_FIELD(TaskStruct, ThreadGroup)) && (0 == LIX_FIELD(TaskStruct, ThreadNode)))
    {
        QWORD signal, flink;

        status = IntKernVirtMemFetchQword(TaskGva + LIX_FIELD(TaskStruct, Signal), &signal);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading the init's signal struct: 0x%08x\n", status);
            return status;
        }

        status = IntKernVirtMemFetchQword(signal + LIX_FIELD(Ungrouped, SignalListHead), &flink);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading from init's signal struct: 0x%08x\n", status);
            return status;
        }

        // Sanity check: 'signal' field is below sizeof(task_struct), which for now we assume that of PAGE_SIZE
        if (flink - TaskGva > PAGE_SIZE)
        {
            ERROR("[ERROR] Signal's struct is not good: 0x%016llx 0x%016llx 0x%016llx\n", flink, signal, TaskGva);
            return INT_STATUS_NOT_SUPPORTED;
        }

        // Detect dynamically the thread node
        LIX_FIELD(TaskStruct, ThreadNode) = (DWORD)(flink - TaskGva);
    }

    InsertTailList(&gLixTasks, &pInitTask->Link);

    if (Task)
    {
        *Task = pInitTask;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskAdd(
    _In_ QWORD TaskGva,
    _In_ QWORD StaticDetected
    )
///
/// @brief Creates and adds a Linux process in the internal list.
///
/// @param[in] TaskGva        The guest virtual address of the "task_struct" kernel object.
/// @param[in] StaticDetected A value greater than 0 suggest that the process was static detected.
///
/// @returns #INT_STATUS_SUCCESS             On success.
/// @returns #INT_STATUS_INVALID_PARAMETER_1 If the first parameter is not a kernel address.
///
{
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_LIX(TaskGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // This is the first call to this function, so create the init task
    if (__unlikely(StaticDetected && IsListEmpty(&gLixTasks)))
    {
        status = IntLixTaskCreateInitTask(TaskGva, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskCreateInitTask failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        QWORD parentTs, realParentTs;
        LIX_TASK_OBJECT *pParent, *pRealParent;

        parentTs = realParentTs = 0;

        status = _IntLixTaskStartMap(TaskGva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] _IntLixTaskStartMap failed for %llx: %08x\n", TaskGva, status);
            return status;
        }

        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, RealParent), sizeof(realParentTs), &realParentTs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the real parent: %08x\n", status);
            goto _finish_task;
        }

        status = _IntLixTaskRead(LIX_FIELD(TaskStruct, Parent), sizeof(parentTs), &parentTs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the parent: %08x\n", status);
            goto _finish_task;
        }

        pParent = IntLixTaskFindByGva(parentTs);
        if (NULL == pParent)
        {
            WARNING("[WARNING] IntLixTaskFindByGva failed for parent 0x%016llx\n", parentTs);

            pParent = IntLixTaskFindByPid(1);
            if (NULL == pParent)
            {
                ERROR("[ERROR] IntLixTaskFindByPid failed for PID 1!\n");
                goto _finish_task;
            }
        }
        else
        {
            IntLixCredsVerify(pParent);
        }

        if (parentTs == realParentTs)
        {
            pRealParent = pParent;
        }
        else
        {
            pRealParent = IntLixTaskFindByGva(realParentTs);

            if (NULL == pRealParent)
            {
                WARNING("[WARNING] IntLixTaskFindByGva failed for real parent 0x%016llx\n", realParentTs);
                pRealParent = pParent;
            }
            else
            {
                IntLixCredsVerify(pRealParent);
            }
        }

        status = IntLixTaskCreate(pParent, pRealParent, TaskGva, StaticDetected != 0, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskCreate failed: 0x%08x\n", status);
        }

_finish_task:
        _IntLixTaskFinishMap();
    }

    return status;
}


static INTSTATUS
IntLixTaskChangeProtectionFlags(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD NewProtection,
    _In_ QWORD NewRootProtection,
    _In_ QWORD Context
    )
///
/// @brief Adjust the protection of a Linux process based on a new set of rules.
///
/// @param[in] Task              The Linux process.
/// @param[in] NewProtection     The new protection flags set.
/// @param[in] NewRootProtection The new root protection flags. (This are the raw flags supplied by the integrator).
/// @param[in] Context           The context provided by the integrator.
///
/// @returns #INT_STATUS_SUCCESS         On Success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If the protection flags haven't changed.
///
{
    INTSTATUS status;
    QWORD oldProtection;

    oldProtection = Task->Protection.Mask;

    if (NewProtection == oldProtection)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == NewProtection)
    {
        LOG("[PROT] Removing %s %s (%llx, %llx, %d) from protection", Task->Exec ? "exec process" : "fork process",
            Task->Comm, Task->Gva, Task->Cr3, Task->Pid);

        IntLixTaskDeactivateProtection(Task);

        Task->Protected = FALSE;

        return INT_STATUS_SUCCESS;
    }

    LOG("[PROT] Changing protection flags for `%s` (Pid %d, ts 0x%016llx): 0x%llx -> 0x%llx\n",
        Task->Comm, Task->Pid, Task->Gva, oldProtection, NewProtection);

    if ((PROC_OPT_PROT_EXPLOIT & NewProtection) != (PROC_OPT_PROT_EXPLOIT & oldProtection))
    {
        if (0 != (PROC_OPT_PROT_EXPLOIT & NewProtection))
        {
            LOG("[PROT] PROC_OPT_PROT_EXPLOIT disabled -> enabled for %s (%llx, %d)\n",
                Task->Comm, Task->Cr3, Task->Pid);

            Task->Protection.Mask |= PROC_OPT_PROT_EXPLOIT;

            status = IntLixTaskActivateExploitProtection(Task);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] Process '%s' (%d, %llx, %llx) will not be exploit-protected: %08x!\n",
                        Task->ProcName, Task->Pid, Task->Gva, Task->Cr3, status);

                Task->Protection.Mask &= ~PROC_OPT_PROT_EXPLOIT;
            }
        }
        else
        {
            LOG("[PROT] PROC_OPT_PROT_EXPLOIT enabled -> disabled for %s (%llx, %d)\n",
                Task->Comm, Task->Cr3, Task->Pid);

            status = IntLixTaskDeactivateExploitProtection(Task);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Process '%s' (%d, %llx, %llx) failed to deactivate protection: %08x\n",
                      Task->ProcName, Task->Pid, Task->Gva, Task->Cr3, status);
            }

            Task->Protection.Mask &= ~PROC_OPT_PROT_EXPLOIT;
        }
    }

    if ((PROC_OPT_REMEDIATE & NewProtection) != (PROC_OPT_REMEDIATE & oldProtection))
    {
        LOG("[PROT] PROC_OPT_REMEDIATE %s for process %s, %d\n",
            0 != (PROC_OPT_REMEDIATE & NewProtection) ? "disabled -> enabled" : "enabled -> disabled",
            Task->Comm, Task->Pid);
    }

    if ((PROC_OPT_KILL_ON_EXPLOIT & NewProtection) != (PROC_OPT_KILL_ON_EXPLOIT & oldProtection))
    {
        LOG("[PROCESS] PROC_OPT_KILL_ON_EXPLOIT %s for process %s, %d\n",
            0 != (PROC_OPT_KILL_ON_EXPLOIT & NewProtection) ? "disabled -> enabled" : "enabled -> disabled",
            Task->Comm, Task->Pid);
    }

    if ((PROC_OPT_PROT_WRITE_MEM & NewProtection) != (PROC_OPT_PROT_WRITE_MEM & oldProtection))
    {
        LOG("[PROCESS] PROC_OPT_PROT_WRITE_MEM %s for process %s, %d\n",
            0 != (PROC_OPT_PROT_WRITE_MEM & NewProtection) ? "disabled -> enabled" : "enabled -> disabled",
            Task->Comm, Task->Pid);
    }

    if ((PROC_OPT_PROT_PTRACE & NewProtection) != (PROC_OPT_PROT_PTRACE & oldProtection))
    {
        LOG("[PROCESS] PROC_OPT_PROT_PTRACE %s for process %s, %d\n",
            0 != (PROC_OPT_PROT_PTRACE & NewProtection) ? "disabled -> enabled" : "enabled -> disabled",
            Task->Comm, Task->Pid);
    }

    if ((PROC_OPT_BETA & NewProtection) != (PROC_OPT_BETA & oldProtection))
    {
        LOG("[PROCESS] PROC_OPT_BETA %s for process %s, %d\n",
            0 != (PROC_OPT_BETA & NewProtection) ? "disabled -> enabled" : "enabled -> disabled",
            Task->Comm, Task->Pid);
    }

    Task->Protected = TRUE;
    Task->Protection.Mask = NewProtection;
    Task->RootProtectionMask = NewRootProtection;
    Task->Context = Context;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixTaskAdjustProtections(
    _In_ const LIX_PROTECTED_PROCESS *ProtProc,
    _In_ BOOLEAN Remove
    )
///
/// @brief Adjusts the protection flags for processes associated with the LIX_PROTECTED_PROCESS object.
///
/// @param[in] ProtProc The protect process pattern.
/// @param[in] Remove   If the protection for the processes matching the given pattern should be removed.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_NOT_NEEDED_HINT If user mode introspection is not enabled.
///
{
    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_MISC_PROCS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    for_each_task(pTask)
    {
        INTSTATUS status;
        QWORD protMask, childProtMask, protBetaMask, protFeedbackMask;
        QWORD context;

        if (pTask->IsThread)
        {
            continue;
        }

        if (!(ProtProc->NamePattern && pTask->Path &&
              IntMatchPatternUtf8(ProtProc->NamePattern, pTask->Path->Name, 0)) &&
            (!IntMatchPatternUtf8(ProtProc->CommPattern, pTask->Comm, INTRO_MATCH_TRUNCATED)))
        {
            continue;
        }

        protMask = Remove ? 0 : ProtProc->Protection.Current;
        context = Remove ? 0 : ProtProc->Context;
        protBetaMask = Remove ? 0 : ProtProc->Protection.Beta;
        protFeedbackMask = Remove ? 0 : ProtProc->Protection.Feedback;

        if (pTask->Context != context)
        {
            pTask->Context = context;
        }

        pTask->Protection.Beta = protBetaMask;
        pTask->Protection.Feedback = protFeedbackMask;

        if (pTask->Protection.Mask == protMask)
        {
            continue;
        }

        status = IntLixTaskChangeProtectionFlags(pTask, protMask, protMask, context);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskChangeProtectionFlags failed for 0x%016llx (Cr3 0x%016llx): 0x%08x\n",
                  pTask->Gva, pTask->Cr3, status);
        }

        // Children should be further down in list (not before this)
        for_next_task(pTask, pChild)
        {
            if (pChild->Exec || pChild->ActualParent != pTask->Gva)
            {
                continue;
            }

            if (Remove)
            {
                childProtMask = 0;
                pChild->Protection.Beta = 0;
                pChild->Protection.Feedback = 0;
            }
            else
            {
                // Need to reset it every time (it may change below for the current child)
                childProtMask = pTask->Protection.Mask;
                pChild->Protection.Beta = pTask->Protection.Beta;
                pChild->Protection.Feedback = pTask->Protection.Feedback;

                context = pTask->Context;

                if (pTask->Cr3 == pChild->Cr3 || 0 == pChild->Cr3)
                {
                    childProtMask &= ~PROC_OPT_PROT_EXPLOIT;
                    childProtMask &= ~PROC_OPT_PROT_CORE_HOOKS;
                }
            }

            status = IntLixTaskChangeProtectionFlags(pChild, childProtMask, pTask->RootProtectionMask, context);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixTaskChangeProtectionFlags failed for 0x%016llx (Cr3 0x%016llx): 0x%08x\n",
                      pChild->Gva, pChild->Cr3, status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskAddProtected(
    _In_ const char *ProcessName,
    _In_ QWORD ProtectionMask,
    _In_ QWORD Context
    )
///
/// @brief Adds a protected process name pattern.
///
/// @param[in] ProcessName    The process name pattern.
/// @param[in] ProtectionMask The protection flags set for this process.
/// @param[in] Context        The context provided by the integrator.
///
/// @returns #INT_STATUS_SUCCESS                On success.
/// @returns #INT_STATUS_INVALID_PARAMETER_1    If the first parameter does not point to a valid memory location.
/// @returns #INT_STATUS_NOT_SUPPORTED          If the pattern length exceeds the 64KB limit.
/// @returns #INT_STATUS_INSUFFICIENT_RESOURCES If there is not enough memory available.
///
{
    size_t nameLen;
    INTSTATUS status;
    LIX_PROTECTED_PROCESS *pProt = NULL;

    if (NULL == ProcessName)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    nameLen = strlen(ProcessName);

    if (nameLen >= 64 * ONE_KILOBYTE)
    {
        ERROR("[ERROR] Names longer than 64K are not supported!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    for_each_task_to_protect(pExtProt)
    {
        if ((pExtProt->NamePattern && 0 == strncasecmp(pExtProt->NamePattern, ProcessName, nameLen + 1)) ||
            0 == strncasecmp(pExtProt->CommPattern, ProcessName, MIN(LIX_COMM_SIZE, nameLen + 1)))
        {
            LOG("[PROT] Process %s already protected as %s with %llx... Update the protection to %llx\n",
                ProcessName, pExtProt->NamePattern ? pExtProt->NamePattern : pExtProt->CommPattern,
                pExtProt->Protection.Original, ProtectionMask);

            pExtProt->Protection.Original = ProtectionMask;
            pExtProt->Protection.Current = ProtectionMask;
            pExtProt->Protection.Beta = 0;
            pExtProt->Protection.Feedback = 0;

            pExtProt->Context = Context;
            pProt = pExtProt;

            break;
        }
    }

    // If not found, add a new entry
    if (NULL == pProt)
    {
        pProt = HpAllocWithTag(sizeof(*pProt), IC_TAG_POBJ);
        if (NULL == pProt)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pProt->NamePattern = HpAllocWithTag(nameLen + 1, IC_TAG_NAME);
        if (NULL == pProt->NamePattern)
        {
            ERROR("[ERROR] Process '%s' will not be protected as there is not enough memory available\n", ProcessName);

            HpFreeAndNullWithTag(&pProt, IC_TAG_NAME);

            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        strlcpy(pProt->NamePattern, ProcessName, nameLen + 1);

        strlcpy(pProt->CommPattern, ProcessName, sizeof(pProt->CommPattern));

        pProt->Protection.Original = ProtectionMask;
        pProt->Protection.Current = ProtectionMask;
        pProt->Protection.Beta = 0;
        pProt->Protection.Feedback = 0;

        pProt->Context = Context;

        IntCamiUpdateProcessProtectionInfo(pProt);

        LOG("[PROT] Process %s / %s protected with %llx\n",
            pProt->CommPattern, pProt->NamePattern, pProt->Protection.Original);

        InsertTailList(&gLixTasksToProtect, &pProt->Link);
    }

    status = IntLixTaskAdjustProtections(pProt, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskAdjustProtection failed for '%s': %08x\n", pProt->CommPattern, status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTaskRemoveProtected(
    _In_ const char *ProcessName
    )
///
/// @brief Removes a pattern of processes to be protected.
///
/// @param[in] ProcessName The process pattern.
///
/// @returns #INT_STATUS_SUCCESS   On success.
/// @returns #INT_STATUS_NOT_FOUND If the provided process pattern does not exist.
///
{
    INTSTATUS status;
    size_t nameLen;
    LIX_PROTECTED_PROCESS *pProt = NULL;

    if (NULL == ProcessName)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    nameLen = strlen(ProcessName);

    for_each_task_to_protect(pExtProt)
    {
        if (0 == strncasecmp(pExtProt->NamePattern, ProcessName, nameLen + 1))
        {
            LOG("Remove process %s from protected list!\n", pExtProt->NamePattern);

            pProt = pExtProt;
            break;
        }
    }

    if (NULL == pProt)
    {
        return INT_STATUS_NOT_FOUND;
    }

    status = IntLixTaskAdjustProtections(pProt, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskAdjustProtection failed for '%s': %08x\n", pProt->CommPattern, status);
    }

    RemoveEntryList(&pProt->Link);

    HpFreeAndNullWithTag(&pProt->NamePattern, IC_TAG_NAME);

    HpFreeAndNullWithTag(&pProt, IC_TAG_POBJ);

    return INT_STATUS_SUCCESS;
}


void
IntLixTaskUpdateProtection(
    void
    )
///
/// @brief Adjusts protection for all active Linux processes.
///
{
    INTSTATUS status;

    for_each_task(pTask)
    {
        const LIX_PROTECTED_PROCESS *pProt = IntLixTaskShouldProtect(pTask);

        if (NULL == pProt)
        {
            IntLixTaskDeactivateProtection(pTask);
        }
        else
        {
            status = IntLixTaskAdjustProtections(pProt, FALSE);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixTaskAdjustProtection failed for '%s': %08x\n", pProt->CommPattern, status);
            }
        }
    }
}


INTSTATUS
IntLixTaskGetAgentsAsCli(
    _Out_writes_bytes_(Length) char *CommandLine,
    _In_ DWORD Length
    )
///
/// @brief Returns a string with the command lines of all active agents.
///
/// @param[out] CommandLine Will contain, upon successful return, the agents command lines.
/// @param[in]  Length      The size of the CommandLine parameter.
///
/// @returns #INT_STATUS_SUCCESS               On success.
/// @returns #INT_STATUS_DATA_BUFFER_TOO_SMALL If the command lines cannot fit in the provided buffer.
///
{
    char *cmd = CommandLine;

    for_each_task(pTask)
    {
        INT32 len;

        if (!pTask->AgentTag)
        {
            continue;
        }

        len = snprintf(cmd, Length, "%s %d ", pTask->Path ? pTask->Path->Name : pTask->Comm, pTask->Pid);
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
IntLixTaskUninit(
    void
    )
///
/// @brief Uninitializes the Linux process subsystem
///
{
    for_each_task(pTask)
    {
        IntLixTaskMarkAgent(pTask);

        RemoveEntryList(&pTask->Link);

        IntLixTaskRemoveEntry(pTask);
    }

    for_each_task_to_protect(pProt)
    {
        RemoveEntryList(&pProt->Link);

        if (NULL != pProt->NamePattern)
        {
            HpFreeAndNullWithTag(&pProt->NamePattern, IC_TAG_NAME);
        }

        HpFreeAndNullWithTag(&pProt, IC_TAG_POBJ);
    }
}


static void
IntLixTaskDumpTree(
    _In_opt_ LIX_TASK_OBJECT *Task,
    _In_ DWORD Level
    )
///
/// @brief Dumps the user mode tasks tree.
///
/// @param[in] Task  The Linux process that will act as the root for the nodes bellow.
/// @param[in] Level The level on the hierarchy this process resides on.
///
{
    DWORD flags;
    INTSTATUS status;

    // Search the first process and start there
    if (NULL == Task)
    {
        for_each_task(pProc)
        {
            if (!pProc->IsThread)
            {
                Task = pProc;
                break;
            }
        }
    }

    if (NULL == Task)
    {
        LOG("We have no processes in the system!\n");
        return;
    }

    if (Level >= 2)
    {
        for (DWORD i = 0; i < Level - 1; i++)
        {
            NLOG("--");
        }

        NLOG("--| ");
    }
    else if (Level >= 1)
    {
        NLOG("|   ");
    }

    status = IntKernVirtMemFetchDword(Task->Gva + LIX_FIELD(TaskStruct, Flags), &flags);
    if (!INT_SUCCESS(status))
    {
        flags = 0;
    }

    if (!Task->IsThread)
    {
        NLOG("%6d/%-6d: %s %-40s CR3: 0x%016llx, prot: %d/%llx, mm_struct: 0x%016llx, task_struct: 0x%016llx, "
             "flags: %08x%s%s, parent: 0x%016llx, real_parent: 0x%016llx\n",
             Task->Pid, Task->Tgid,
             Task->Exec ? "EXEC" : "FORK",
             Task->ProcName,
             Task->Cr3,
             Task->Protected, Task->Protection.Mask,
             Task->MmGva,
             Task->Gva,
             flags,
             Task->Interpreter ? ", by interpreter " : "",
             Task->Interpreter ? Task->Interpreter : "",
             Task->Parent, Task->RealParent);
    }
    else
    {
        char newComm[LIX_COMM_SIZE] = {0};

        status = IntKernVirtMemRead(Task->Gva + LIX_FIELD(TaskStruct, Comm),
                                    sizeof(newComm) - 1,
                                    newComm,
                                    NULL);
        if (!INT_SUCCESS(status))
        {
            newComm[0] = '\0';
        }

        NLOG("%6d/%-6d: %-16s / %-16s task_struct: 0x%016llx, prot: %d/%llx, flags: %08x, parent: 0x%016llx, "
             "real_parent: 0x%016llx\n",
             Task->Pid, Task->Tgid, Task->Comm, newComm, Task->Gva, Task->Protected,
             Task->Protection.Mask, flags, Task->Parent, Task->RealParent);
    }

    for_each_task(pProc)
    {
        if (pProc == Task)
        {
            continue;
        }

        if (!pProc->IsThread && pProc->Parent == Task->Gva)
        {
            IntLixTaskDumpTree(pProc, Level + 1);
        }
        else if (pProc->IsThread && pProc->Tgid == Task->Pid)
        {
            if (Task->IsThread)
            {
                IntLixTaskDumpTree(pProc, Level);
            }
            else
            {
                IntLixTaskDumpTree(pProc, Level + 1);
            }
        }
    }
}


static void
IntLixTaskDumpKernelThreadTree(
    _In_opt_ LIX_TASK_OBJECT *Thread,
    _In_ DWORD Level
    )
///
/// @brief Dumps the kthreads tree.
///
/// This function will dump all kthreads created by another kthread. If the Thread parameter is NULL then the
/// first created kthread will be on the top of the hierarchy.
///
/// @param[in] Thread The starting kthread.
/// @param[in] Level  The hierarchy level.
///
{
    DWORD i, flags;
    INTSTATUS status;

    // Search the first kernel thread and start there
    if (NULL == Thread)
    {
        for_each_task(pThread)
        {
            if (pThread->IsThread && pThread->KernelMode)
            {
                Thread = pThread;
                break;
            }
        }
    }

    if (NULL == Thread || !Thread->IsThread || !Thread->KernelMode)
    {
        if (Level == 0)
        {
            LOG("We have no kernel thread in the system!\n");
        }

        return;
    }

    for (i = 0; i < Level; i++)
    {
        NLOG("--");
    }

    NLOG("> ");

    status = IntKernVirtMemFetchDword(Thread->Gva + 2 * sizeof(QWORD) + sizeof(DWORD), &flags);
    if (!INT_SUCCESS(status))
    {
        flags = 0;
    }

    NLOG("%6d/%-6d : %-16s task_struct: 0x%016llx, prot: %d/%llx, flags: %08x\n",
         Thread->Pid, Thread->Tgid, Thread->Comm, Thread->Gva,
         Thread->Protected, Thread->Protection.Mask, flags);

    for_each_task(pThread)
    {
        if (pThread->Parent == Thread->Gva)
        {
            IntLixTaskDumpKernelThreadTree(pThread, Level + 1);
        }
    }
}


void
IntLixTaskDumpAsTree(
    void
    )
///
/// @brief Dump the process tree.
///
{
    IntLixTaskDumpTree(NULL, 0);
    IntLixTaskDumpKernelThreadTree(NULL, 0);
}


void
IntLixTaskDump(
    void
    )
///
/// @brief Dumps the process list.
///
{
    for_each_task(pTask)
    {
        if (!pTask->IsThread)
        {
            LOG("Process %s (%s), PID: %d, TS 0x%016llx, Mm 0x%016llx, Parent 0x%016llx, RealParent 0x%016llx, "
                "Protected: %d/%llx\n", !pTask->Exec ? "(no exec)" : pTask->Path ? pTask->Path->Path : "(no path)",
                pTask->Comm, pTask->Pid, pTask->Gva, pTask->MmGva,
                pTask->Parent, pTask->RealParent,
                pTask->Protected, pTask->Protection.Mask);

            if (pTask->Protection.Mask & PROC_OPT_PROT_EXPLOIT)
            {
                list_for_each(pTask->Vmas, LIX_VMA, pVma)
                {
                    LOG("  [%016llx -> %016llx] : %08llx [file @%016llx] @ %016llx Hooked=%d (%c%c%c)\n",
                        pVma->Start, pVma->End, pVma->Flags, pVma->File, pVma->Gva, pVma->Hook ? 1 : 0,
                        (pVma->Flags & VM_EXEC) ? 'X' : '-',
                        (pVma->Flags & VM_WRITE) ? 'W' : '-',
                        (pVma->Flags & VM_READ) ? 'R' : '-');
                }

                IntLixMmListVmas(pTask->MmGva, pTask);
            }

            // Parse the list again for this process threads
            for_each_task(pThr)
            {
                if (!pThr->IsThread)
                {
                    continue;
                }

                if (pThr->Tgid != pTask->Tgid)
                {
                    continue;
                }

                LOG("----> Thread %s %d/%d @ 0x%016llx, Parent 0x%016llx, RealParent 0x%016llx, Protected: %d/%llx\n",
                    pThr->Comm, pThr->Pid, pThr->Tgid, pThr->Gva,
                    pThr->Parent, pThr->RealParent,
                    pThr->Protected, pThr->Protection.Mask);
            }
        }
    }

    for_each_task(pKThread)
    {
        if (pKThread->IsThread && pKThread->KernelMode)
        {
            LOG("Kernel Thread %s, P(TG)ID %d/%d, CR3 0x%016llx, TS 0x%016llx, Parent 0x%016llx, "
                "RealParent 0x%016llx, ActualParent 0x%016llx, Protected: %d/%llx\n",
                pKThread->Comm, pKThread->Pid, pKThread->Tgid,
                pKThread->Cr3,
                pKThread->Gva,
                pKThread->Parent,
                pKThread->RealParent,
                pKThread->ActualParent,
                pKThread->Protected,
                pKThread->Protection.Mask);
        }
    }
}


void
IntLixTaskDumpProtected(
    void
    )
///
/// @brief Dumps the list with processes that Introcore should protect.
///
{
    DWORD i = 0;

    for_each_task_to_protect(pProt)
    {
        LOG("# %04d %s, %llx, '%s'\n",
            i,
            pProt->CommPattern,
            pProt->Protection.Original,
            pProt->NamePattern ? pProt->NamePattern : "(none)");

        i++;
    }
}


INTSTATUS
IntLixTaskIterateTasks(
    _In_ PFUNC_LixTaskIterateTasks Callback
    )
///
/// @brief Call the Callback parameter for each task saved internally.
///
/// @param[in] Callback The callback to be called for each task.
///
/// @returns #INT_STATUS_SUCCESS             On success.
/// @returns #INT_STATUS_INVALID_PARAMETER_1 If an invalid callback is supplied.
///
{
    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    for_each_task(pTask)
    {
        INTSTATUS status = Callback(pTask);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Callback failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


BOOLEAN
IntLixTaskGuestTerminating(
    void
    )
///
/// @brief Check whether the guest OS is terminating or not.
///
/// This function will firstly attempt to compare the "system_state" kernel variable with the "Running" value.
/// Linux documentation tells us that any state value greater than running means the system is either going down
/// or it's suspending/hibernating.  However, is some cases we may not be able to access the "system_state"
/// and we apply the following heuristic to determine if the guest is shutting down:
///   * A kernel panic was triggered.
///   * The task list is empty.
///   * There are less than 6 tasks running and one of them is a shutdown task. See #gLixTerminatingTasks for
///     the list with all shutdown tasks.
/// If any of these conditions is met we consider the guest state as terminating.
///
/// @returns TRUE  If the guest is terminating.
/// @returns FALSE Otherwise.
///
{
    LIX_TASK_OBJECT *pTerminateTask = NULL;
    WORD userModeTasks = 0;
    int systemState = IntLixGuestGetSystemState();

    if (systemState > (int)(LIX_FIELD(Ungrouped, Running)))
    {
        LOG("[LIX-GUEST] Found system state '%d'\n", systemState);
        return TRUE;
    }

    if (gGuest.BugCheckInProgress)
    {
        return TRUE;
    }

    if (IsListEmpty(&gLixTasks))
    {
        return TRUE;
    }

    for_each_task(pTask)
    {
        if (pTask->KernelMode)
        {
            continue;
        }

        userModeTasks++;

        if (pTerminateTask != NULL)
        {
            continue;
        }

        for (DWORD index = 0; index < ARRAYSIZE(gLixTerminatingTasks); index++)
        {
            if (pTask->Path &&
                0 == strncmp(pTask->Path->Name, gLixTerminatingTasks[index], strlen(gLixTerminatingTasks[index]) + 1))
            {
                pTerminateTask = pTask;
            }

            if (0 == strncmp(pTask->Comm, gLixTerminatingTasks[index], sizeof(pTask->Comm)))
            {
                pTerminateTask = pTask;
            }
        }
    }

    if (pTerminateTask == NULL)
    {
        return FALSE;
    }

    LOG("[LIX-GUEST] Found shutdown/reboot task '%s'\n", pTerminateTask->Comm);

    if (userModeTasks > 6)
    {
        return FALSE;
    }

    return TRUE;
}


INTSTATUS
IntLixAccessRemoteVmHandler(
    _In_ void *Detour
    )
///
/// @brief Detour handler for __access_remote_vm.
///
/// This function will deny any attempt of a process to alter the memory space of another process. Even though
/// _access_remote_vm is also used to also perform reads, the detour handler inside the OS will filter the
/// events and only the ones performing writes will trigger any actions.
///
/// @param[in] Detour Unused.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_TASK_OBJECT *pOriginator = IntLixTaskGetCurrent(gVcpu->Index);
    LIX_TASK_OBJECT *pVictim = IntLixTaskFindByMm(gVcpu->Regs.R8);
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action = introGuestNotAllowed;
    INTRO_ACTION_REASON reason = introReasonUnknown;
    QWORD dstAddress = gVcpu->Regs.R9;
    QWORD address = gVcpu->Regs.R10;
    DWORD length = (DWORD)(gVcpu->Regs.R11);

    UNREFERENCED_PARAMETER(Detour);

    STATS_ENTER(statsExceptionsUser);

    if (!(pVictim->Protection.Mask & PROC_OPT_PROT_WRITE_MEM))
    {
        action = introGuestAllowed;
        goto _exit;
    }

    status = IntExceptUserGetOriginator(pOriginator, FALSE, address, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] IntExceptUserGetOriginator failed with status: 0x%08x\n", status);
        goto _exit;
    }

    status = IntExceptGetVictimProcess(pVictim, dstAddress, length, ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] IntExceptGetVictimProcess failed with status: 0x%08x\n", status);
        goto _exit;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

_exit:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_WRITE_MEM, pVictim, &action, &reason))
    {
        IntLixTaskSendInjectionEvent(pOriginator, pVictim, action, reason);
    }

    IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_WRITE_MEM, pVictim, &action);

    status = IntDetSetReturnValue(Detour, &gVcpu->Regs, action == introGuestAllowed ? 0 : -EACCES);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetoursGstSetReturnValue failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}
