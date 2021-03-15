/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixcred.h"
#include "alerts.h"
#include "crc32.h"
#include "guests.h"
#include "lixfiles.h"
#include "lixmm.h"
#include "lixprocess.h"
#include "lixstack.h"
#include "kernvm.h"


///
/// @brief The beginning of the cred structure as defined by linux kernel.
///
/// Subject to change, but these fields are the same since 2.6.32 (maybe older too...)
///
typedef struct _INTERNAL_CRED
{
    int usage;

    unsigned int uid;
    unsigned int guid;
    unsigned int suid;
    unsigned int sgid;
    unsigned int euid;
    unsigned int egid;
    unsigned int fsuid;
    unsigned int fsgid;
} INTERNAL_CRED;


///
/// @brief The list head of the credentials structures protected by introcore.
///
static LIST_HEAD gCreds = LIST_HEAD_INIT(gCreds);

///
/// @brief The guest virtual address of the "struct cred" that is currently being mapped.
///
static QWORD gCredGva = 0;

///
/// @brief The mapping point of the cred structure.
///
static void *gCredMap1 = NULL;

///
/// @brief The secondary mapping point of the cred structure.
///
/// The mapping point of second page if the cred structure that is currently mapped
/// doesn't fit in one single page.
///
static void *gCredMap2 = NULL; ///< The second mapping point of the cred structure if it doesn't fit in the f

///
/// @brief Directories where libraries changing credentials should be located.
///
char *gLibPaths[] =
{
    "/lib/*",
    "/lib64/*",
    "/lib32/*",
    "/usr/lib/*",
    "/usr/lib32/*",
    "/usr/lib64/*",
    "/@/.snapshots/*/snapshots/lib64/*",
    "/@/.snapshots/*/snapshots/lib32/*",
    "/@/.snapshots/*/snapshots/lib/*",
    "/@/.snapshots/*/snapshot/lib64/*",
    "/@/.snapshots/*/snapshot/lib32/*",
    "/@/.snapshots/*/snapshot/lib/*",

};

///
/// @brief Libraries allowed to change process credentials.
///
char *gLibFiles[] =
{
    "libc-2.??.so",
    "libpthread-2.??.so",
};


static void
IntLixCredUninitMap(
    void
    )
///
/// @brief Unmaps the cred structure previously mapped by #IntLixCredInitMap.
///
{
    if (NULL != gCredMap1)
    {
        IntVirtMemUnmap(&gCredMap1);

        gCredMap1 = NULL;
    }

    if (NULL != gCredMap2)
    {
        IntVirtMemUnmap(&gCredMap2);

        gCredMap2 = NULL;
    }

    gCredGva = 0;
}



static INTSTATUS
IntLixCredInitMap(
    _In_ QWORD CredGva
    )
///
/// @brief Maps a cred structure in order to calculate the checksum in a faster manner.
///
/// @param[in] CredGva The guest virtual address of the creds structure to be mapped.
///
/// @return INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntVirtMemMap(CredGva, PAGE_REMAINING(CredGva), gGuest.Mm.SystemCr3, 0, &gCredMap1);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", CredGva, status);
        goto _cleanup_and_fail;
    }

    if (PAGE_COUNT(CredGva, LIX_FIELD(Cred, Sizeof)) > 1)
    {
        status = IntVirtMemMap((CredGva & PAGE_MASK) + PAGE_SIZE, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &gCredMap2);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", (CredGva & PAGE_MASK) + PAGE_SIZE, status);
            goto _cleanup_and_fail;
        }
    }

    gCredGva = CredGva;

    return INT_STATUS_SUCCESS;

_cleanup_and_fail:
    IntLixCredUninitMap();

    return status;
}


static void
IntLixCredsDump(
    _In_ const LIX_CREDS *Creds
    )
///
/// @brief Logs information about a cred structure.
///
/// @param[in] Creds The LIX_CREDS structure associated with the credentials.
///
{
    INTSTATUS status;
    INTERNAL_CRED *c = NULL;

    if (NULL == Creds)
    {
        return;
    }

    status = IntVirtMemMap(Creds->Gva, sizeof(*c), gGuest.Mm.SystemCr3, 0, &c);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for gva %llx\n", Creds->Gva);
        return;
    }

    LOG("--> uid = %04d, guid = %04d, suid = %04d, sgid = %04d, euid = %04d, egid = %04d, fsuid = %04d, fsgid = %04d\n",
        c->uid, c->guid, c->suid, c->sgid, c->euid, c->egid, c->fsuid, c->fsgid);

    IntVirtMemUnmap(&c);
}


static void
IntLixTaskSendCredViolationEvent(
    _In_ const LIX_TASK_OBJECT *Task
    )
///
/// @brief Sends an EVENT_INTEGRITY_VIOLATION event.
///
/// @param[in] Task The process accused of credential violence.
///
{
    EVENT_INTEGRITY_VIOLATION *pEvent = &gAlert.Integrity;
    memzero(pEvent, sizeof(*pEvent));

    INTSTATUS status = IntKernVirtMemFetchQword(Task->Gva + LIX_FIELD(TaskStruct, Cred), &pEvent->BaseAddress);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
    }

    pEvent->VirtualAddress = pEvent->BaseAddress;
    pEvent->Size = LIX_FIELD(Cred, Sizeof);

    pEvent->Header.Flags = ALERT_FLAG_LINUX;
    pEvent->Header.Flags |= ALERT_FLAG_ASYNC;

    if (gGuest.KernelBetaDetections)
    {
        pEvent->Header.Flags = ALERT_FLAG_BETA;
    }

    pEvent->Header.Action = introGuestNotAllowed;
    pEvent->Header.Reason = introReasonNoException;
    pEvent->Header.MitreID = idAccessToken;

    pEvent->Header.CpuContext.Valid = FALSE;
    pEvent->Header.CurrentProcess.Valid = FALSE;

    IntAlertFillLixProcess(Task, &pEvent->Originator.Process);
    IntAlertFillLixProcess(Task, &pEvent->Victim.Process);

    pEvent->Victim.Type = introObjectTypeCreds;
    memcpy(pEvent->Victim.Name, VICTIM_PROCESS_CREDENTIALS, sizeof(VICTIM_PROCESS_CREDENTIALS));

    IntAlertFillVersionInfo(&pEvent->Header);

    pEvent->WriteInfo.Size = 0;

    LOG("[CRED] [INTEGRITY VIOLATION] Modified credentials for process (%d %llx %s) at address %llx.\n",
        Task->Pid, Task->Gva, Task->Comm, pEvent->VirtualAddress );
    IntLixCredsDump(Task->Creds);
    LOG("[CRED] ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ROOTKIT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: %08x\n", status);
    }

}


static DWORD
IntLixCredCalculateCrc32Region(
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _In_ DWORD InitialCrc
    )
///
/// @brief Calculates the CRC32 checksum for a memory region representing a slice of the cred structure.
///
/// The given region may not fit in a single page so we must check the page limits in order to determine where the
/// requested region is mapped. There are three cases:
///
///    1. Whole region is in the first page
///    2. Region is split in two pages
///    3. Whole region is in second page
///
/// @param[in] Offset     The offset in cred structure where the region begins.
/// @param[in] Size       The size of the region.
/// @param[in] InitialCrc The initial crc32 checksum.
///
/// @returns The CRC32 checksum of the region.
///
{
    DWORD crc = InitialCrc;

    // Three cases:

    if ((gCredGva & PAGE_OFFSET) + Offset + Size < PAGE_SIZE)
    {
        return Crc32Compute((BYTE *)gCredMap1 + Offset, Size, crc);
    }

    if ((gCredGva & PAGE_OFFSET) + Offset <  PAGE_SIZE)
    {
        crc = Crc32Compute((BYTE *)gCredMap1 + Offset, PAGE_REMAINING(gCredGva + Offset), crc);

        return Crc32Compute((BYTE *)gCredMap2, (gCredGva + Offset + Size) & PAGE_OFFSET, crc);
    }

    return Crc32Compute((BYTE *)gCredMap2 + ((gCredGva + Offset) & PAGE_OFFSET), Size, crc);
}


static INTSTATUS
IntLixCredCalculateChecksum(
    _In_ QWORD CredGva,
    _Out_ DWORD *Checksum
    )
///
/// @brief Calculates the CRC32 checksum for a cred structure.
///
/// Will calculate the checksum only for structure regions that actually represent credentials and will ignore
/// fields that may change such as usage, rcu. Thus, we were able to identify three regions:
///
/// 1. [0, min(UsageOffset, RcuOffset))
/// 2. [(min(UsageOffset, RcuOffset) as X) + sizeof(X), max(UsageOffset, RcuOffset))
/// 3. [(max(UsageOffset, RcuOffset) as X) + sizeof(X), sizeof(cred))
///
/// We assume that sizeof(struct cred.usage) is 4 and sizeof(struct cred.rcu) is 16.
///
/// @param[in]  CredGva  The guest virtual address of the cred structure.
/// @param[out] Checksum Upon successful return will contain the checksum of the structure.
///
/// @return INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    static DWORD range[4] = {DWORD_MAX};

    if (range[0] == DWORD_MAX)
    {
        if (LIX_FIELD(Cred, Usage) < LIX_FIELD(Cred, Rcu))
        {
            range[0] = LIX_FIELD(Cred, Usage);
            range[1] = range[0] + 4;
            range[2] = LIX_FIELD(Cred, Rcu);
            range[3] = range[2] + 16;
        }
        else
        {
            range[0] = LIX_FIELD(Cred, Rcu);
            range[1] = range[0] + 16;
            range[2] = LIX_FIELD(Cred, Usage);
            range[3] = range[2] + 4;
        }
    }

    status = IntLixCredInitMap(CredGva);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *Checksum = INITIAL_CRC_VALUE;

    if (range[0] > 0)
    {
        *Checksum = IntLixCredCalculateCrc32Region(0, range[0], *Checksum);
    }

    *Checksum = IntLixCredCalculateCrc32Region(range[1], range[2] - range[1], *Checksum);

    if (range[3] < LIX_FIELD(Cred, Sizeof))
    {
        *Checksum = IntLixCredCalculateCrc32Region(range[3], LIX_FIELD(Cred, Sizeof) - range[3], *Checksum);
    }

    IntLixCredUninitMap();

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixCredAdd(
    _In_ QWORD CredsGva,
    _Out_ LIX_CREDS **Creds
    )
///
/// @brief Adds a cred structure in the integrity protected credentials list.
///
/// @param[in] CredsGva The guest virtual address of the cred structure.
/// @param[in] Creds    Will contain upon success the reference to the LIX_CRED structure.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If tokens protection is not activated.
/// @return INT_STATUS_INVALID_PARAMETER_1 If the given creds GVA is not a kernel pointer.
/// @return INT_STATUS_INVALID_PARAMETER_2 If the Creds parameter does not point to a valid memory region.
/// @return INT_STATUS_INSUFFICIENT_RESOURCES If there was not enough memory available.
///
{
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_LIX(CredsGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Creds)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    *Creds = NULL;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CREDS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    list_for_each(gCreds, LIX_CREDS, pExtCreds)
    {
        if (CredsGva == pExtCreds->Gva)
        {
            // Maybe do an integrity check here?
            pExtCreds->RefCount++;
            *Creds = pExtCreds;

            return INT_STATUS_SUCCESS;
        }
    }

    LIX_CREDS *pCreds = HpAllocWithTag(sizeof(LIX_CREDS), IC_TAG_CRED);
    if (NULL == pCreds)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pCreds->Gva = CredsGva;
    pCreds->RefCount = 1;

    status = IntLixCredCalculateChecksum(CredsGva, &pCreds->Checksum);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCredCalculateChecksum failed for 0x%llx. Status: 0x%08x\n", CredsGva, status);

        HpFreeAndNullWithTag(&pCreds, IC_TAG_CRED);

        return status;
    }

    InsertTailList(&gCreds, &pCreds->Link);

    *Creds = pCreds;

    return INT_STATUS_SUCCESS;
}


void
IntLixCredRemove(
    _In_ LIX_CREDS **Creds
    )
///
/// @brief Removes the integrity protection for the credentials set that belong to a process.
///
/// This function will decrement the credentials refcount and will completely remove them
/// when the refcount reaches 0.
///
/// @param[in] Creds The credentials to be unprotected.
///
{
    LIX_CREDS *pCreds = *Creds;

    *Creds = NULL;

    if (NULL == pCreds)
    {
        return;
    }

    if (pCreds->RefCount == 0)
    {
        ERROR("[ERROR] Refcount for creds %llx is already 0!\n", pCreds->Gva);
        IntBugCheck();
    }

    if (0 == --pCreds->RefCount)
    {
        RemoveEntryList(&pCreds->Link);
        HpFreeAndNullWithTag(&pCreds, IC_TAG_CRED);
    }
}


static INTSTATUS
IntLixCredCheckIntegrity(
    _In_ LIX_CREDS *Creds,
    _In_ BOOLEAN Update,
    _Out_ BOOLEAN *Valid
    )
///
/// @brief Checks if the credentials have been altered.
///
/// @param[in]  Creds  The credentials set.
/// @param[in]  Update Whether the checksum should be updated if changed or not.
/// @param[out] Valid  Will contain upon successful return the check result.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If tokens protection is not enabled.
/// @return INT_STATUS_INVALID_PARAMETER_1 If the Creds parameter does not point to a valid LIX_CREDS object.
/// @return INT_STATUS_INVALID_PARAMETER_2 If the Valid parameter does not represent a valid memory region.
///
{
    INTSTATUS status;
    DWORD checksum;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CREDS))
    {
        *Valid = TRUE;
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == Creds)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntLixCredCalculateChecksum(Creds->Gva, &checksum);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCredCalculateChecksum failed for %llx (refcount: %d): 0x%08x\n",
              Creds->Gva, Creds->RefCount, status);
        return status;
    }

    *Valid = TRUE;

    if (__unlikely(checksum != Creds->Checksum))
    {
        if (Update)
        {
            Creds->Checksum = checksum;
        }

        *Valid = FALSE;
    }

    return INT_STATUS_SUCCESS;
}


void
IntLixCredsVerify(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Verifies whether the credentials of a process has been altered or not.
///
/// @param[in] Task The Linux process.
///
{
    BOOLEAN valid;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CREDS))
    {
        return;
    }

    if (NULL == Task->Creds)
    {
        return;
    }

    INTSTATUS status = IntLixCredCheckIntegrity(Task->Creds, FALSE, &valid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCredCheckIntegrity failed for task '%s' (%d, 0x%llx)\n",
              Task->ProcName, Task->Pid, Task->Gva);
        return;
    }

    if (valid)
    {
        return;
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_TOKEN_STEAL)
    {
        Task->Dpi.StolenTokens = TRUE;
    }

    IntLixTaskSendCredViolationEvent(Task);
}


static void
IntLixCredAnalyzeStack(
    _In_ LIX_TASK_OBJECT *Task,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief Analyze the user mode stack of a process that is patching it's credentials.
///
/// This function will check if the transition from user to kernel was triggered from a
/// known user mode library. See #gLibFiles for the list of libraries allowed to perform this
/// action.
///
/// @param[in]  Task   The Linux process.
/// @param[out] Action The action that should be further taken for this event.
/// @param[out] Reason The reason for the taken action.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_TRAP_FRAME trapFrame = { 0 };
    LIX_VMA vma = { 0 };
    char *pFilePath = NULL;
    DWORD len;

    *Action = introGuestNotAllowed;
    *Reason = introReasonNoException;

    status = IntLixTaskGetTrapFrame(Task, &trapFrame);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskGetTrapFrame failed with status: 0x%08x\n", status);

        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;

        return;
    }

    status = IntLixMmFetchVma(Task, trapFrame.Rip, &vma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmFetchVad failed for RIP %llx: %08x\n", trapFrame.Rip, status);

        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;

        return;
    }

    status = IntLixFileGetPath(vma.File, &pFilePath, &len);
    if (status == INT_STATUS_INVALID_DATA_SIZE)
    {
        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileGetPath filed for file @ 0x%016llx : %08x\n", vma.File, status);
    }
    else if (pFilePath)
    {
        char *pFileName = NULL;
        BOOLEAN found = FALSE;

        for (DWORD i = 0; i < ARRAYSIZE(gLibPaths); i++)
        {
            if (glob_match_utf8(gLibPaths[i], pFilePath, FALSE, FALSE))
            {
                found = TRUE;
                break;
            }
        }

        if (!found)
        {
            goto _out;
        }

        for (; len > 0; len--)
        {
            if (pFilePath[len] == '/')
            {
                pFileName = &pFilePath[len + 1];
                break;
            }
        }

        if (NULL == pFileName)
        {
            pFileName = pFilePath;
        }

        for (DWORD i = 0; i < ARRAYSIZE(gLibFiles); i++)
        {
            if (glob_match_utf8(gLibFiles[i], pFileName, FALSE, FALSE))
            {
                found = TRUE;
                break;
            }
        }

        if (found)
        {
            *Action = introGuestAllowed;
            *Reason = introReasonAllowed;
        }
    }

_out:
    if (*Action != introGuestAllowed)
    {
        LOG("[WARNING] [LIX-CRED] Return address is inside '%s'\n", pFilePath);
    }
}


INTSTATUS
IntLixCommitCredsHandle(
    _In_ void *Detour
    )
///
/// @brief Detour handler for "commit_creds" function.
///
/// Because a process is able to change it's credentials (by calling setuid(), setgid(), etc) we have
/// to keep track of these changes. The kernel is nice and creates a new "cred" structure for any change,
/// then calls "commit_creds" to install the new credentials set on the current task. However, this new
/// credentials set is based on the previous one which may have been already altered. So, in order
/// to avoid registering an altered credentials set as a clean one, we make one last integrity check
/// on the current set.
///
/// This function also checks if the syscall that triggered this change was performed from a known
/// user mode library. Otherwise, a feedback only alert will be sent.
///
/// @param[in] Detour Unused.
///
/// @return INT_STATUS_SUCCESS on success.
///
{
    INTSTATUS status;
    LIX_CREDS *newCreds = NULL;

    UNREFERENCED_PARAMETER(Detour);

    LIX_TASK_OBJECT *pTask = IntLixTaskFindByGva(gVcpu->Regs.R8);
    if (NULL == pTask)
    {
        ERROR("[ERROR] IntLixTaskGetCurrent returned NULL\n");
        return INT_STATUS_SUCCESS;
    }

    if (pTask->KernelMode)
    {
        return INT_STATUS_SUCCESS;
    }

    if (LIX_FIELD(Info, CredAltered))
    {
        DWORD in;

        status = IntKernVirtMemFetchDword(pTask->Gva + LIX_FIELD(TaskStruct, InExecve), &in);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchDword failed for %llx with status: %08x\n",
                    pTask->Gva + LIX_FIELD(TaskStruct, InExecve), status);
        }
        else if (0 == (in & BIT(LIX_FIELD(TaskStruct, InExecveBit))))
        {
            // We should make one last check to be sure they haven't changed in the meantime
            IntLixCredsVerify(pTask);
        }
    }
    else
    {
        IntLixCredsVerify(pTask);
    }

    status = IntLixCredAdd(gVcpu->Regs.R9, &newCreds);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCredAdd failed for %s (%d 0x%llx). Status: 0x%08x\n",
              pTask->Comm, pTask->Pid, pTask->Gva, status);
    }

    IntLixCredRemove(&pTask->Creds);
    pTask->Creds = newCreds;

    return INT_STATUS_SUCCESS;
}
