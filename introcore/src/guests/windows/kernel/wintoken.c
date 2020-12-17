/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wintoken.h"
#include "winprocess.h"
#include "winprocesshp.h"
#include "decoder.h"
#include "hook.h"
#include "drivers.h"
#include "alerts.h"
#include "winpool.h"
#include "gpacache.h"

///
/// @file wintoken.c
///
/// @brief This file handles token steal detection and token privilege protection.
///
/// This module will assure, through integrity protection, once every second, that there are no tokens
/// which are assigned to two processes simultaneously. If two processes share the same token, it means
/// that either some rootkit or some kernel exploit leveraging some arbitrary writes has stolen a token
/// (most probably a more privileged one) and assigned it to a malicious process. In this case, the
/// introspection engine will raise an alert.
/// Moreover, the privileges field in the token structures are protected against modifications. Note that,
/// due to some privilege escalation, a process might exploit some vulnerability such that the assigned
/// privileges are increased, for example CVE-2020-0796 leverages such a vulnerability in the srv2.sys driver
/// so that it gains SYSTEM privileges. The privileges protection is available, due to performance reasons,
/// only on dynamically detected processes (e.g. processes that start after introspection engine initializes),
/// or on all processes on systems which support sub page protection (SPP). The performance improvement in this case
/// is provided by the fact that, once introspection engine initializes, all the token allocations are forced to
/// one page, thus there will not be extra exits outside the protected structure. It is also worth mentioning that
/// dynamic processes can have tokens which are allocated before introspection engine initialization. For this purpose
/// we will check that those allocations have the size of a 4kb page.
/// Note that, on static detected processes introspection engine will verify the assigned privileges to every process
/// once every second, through the integrity mechanism, but due to the fact that, on detection, the LPE has already
/// been executed and the vulnerability leveraged, the introspection engine cannot enforce protection in these case,
/// meaning that rewriting the privileges would be futile, since the process had very high privileges for around
/// 1 second, which is more than enough to provoke damage and enforce persistence on the system.
/// The checks performed on integrity on privileges are:
/// 1. The Present field inside Privileges should not increase. That means, no bits should be 1 if they
/// were previously 0. Note that present privileges may decrease.
/// 2. Any bit set in the Enabled field of Privileges should also be set in the Present field. As the kernel checks
/// against the Present bitfield when increasing a privilege in the Enabled bitfield, but when checking the privileges
/// before accessing a resource, the kernel only checks the Enabled bitfield, we should ensure that there is a
/// consistency between those fields.
///
///


extern LIST_HEAD gWinProcesses;


static INTSTATUS
IntWinTokenPrivsHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

static INTSTATUS
IntWinTokenPrivsHandleSwap(
    _In_opt_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    );

static void
IntWinTokenPrivsSendEptAlert(
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an #EVENT_EPT_VIOLATION for a token privileges violation.
///
/// @param[in]  Originator  The originator driver which has written over the privileges.
/// @param[in]  Victim      Describes the victim of the given violation.
/// @param[in]  Action      The action which was decided to be taken by the exceptions engine.
/// @param[in]  Reason      The reason why the given action was given.
///
{
    EVENT_EPT_VIOLATION *pEpt = &gAlert.Ept;
    INTSTATUS status;

    memzero(pEpt, sizeof(*pEpt));

    pEpt->Header.Action = Action;
    pEpt->Header.Reason = Reason;
    pEpt->Header.MitreID = idAccessToken;

    IntAlertFillCpuContext(TRUE, &pEpt->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(Originator, pEpt);
    IntAlertEptFillFromVictimZone(Victim, pEpt);

    pEpt->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_TOKEN_PRIVS, Reason);

    if (Victim->Object.WinProc->SystemProcess)
    {
        pEpt->Header.Flags |= ALERT_FLAG_SYSPROC;
    }

    IntAlertFillWinProcessByCr3(Victim->Object.WinProc->Cr3, &pEpt->Header.CurrentProcess);

    IntAlertFillCodeBlocks(Originator->Original.Rip, gVcpu->Regs.Cr3, FALSE, &pEpt->CodeBlocks);
    IntAlertFillExecContext(gVcpu->Regs.Cr3, &pEpt->ExecContext);

    IntAlertFillVersionInfo(&pEpt->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEpt, sizeof(*pEpt));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static void
IntWinTokenPrivsSendIntegrityAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an #EVENT_INTEGRITY_VIOLATION when checks over the token privileges have failed.
///
/// @param[in]  Victim  The victim, which is denoted by the process for which the privileges are increased.
/// @param[in]  Action  The action taken by the exceptions engine.
/// @param[in]  Reason  The reason for which the given action has been taken.
///
{
    INTSTATUS status;
    EVENT_INTEGRITY_VIOLATION *pIntViol;

    pIntViol = &gAlert.Integrity;
    memzero(pIntViol, sizeof(*pIntViol));

    pIntViol->Header.Flags |= IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_TOKEN_PRIVS, Reason);

    // Force de-activation of ALERT_FLAG_NOT_RING0. We're always in ring0.
    pIntViol->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    pIntViol->Header.Flags |= ALERT_FLAG_ASYNC;

    pIntViol->Header.Action = Action;
    pIntViol->Header.Reason = Reason;
    pIntViol->Header.MitreID = idAccessToken;

    pIntViol->Victim.Type = Victim->Object.Type;

    memcpy(pIntViol->Victim.Name, VICTIM_TOKEN_PRIVILEGES, sizeof(VICTIM_TOKEN_PRIVILEGES));

    IntAlertFillWinProcess(Victim->Object.Process, &pIntViol->Originator.Process);
    IntAlertFillWinProcess(Victim->Object.Process, &pIntViol->Victim.Process);
    IntAlertFillWinProcess(Victim->Object.Process, &pIntViol->Header.CurrentProcess);

    IntAlertFillWriteInfo(Victim, &pIntViol->WriteInfo);

    IntAlertFillCpuContext(FALSE, &pIntViol->Header.CpuContext);

    // We can't know from what CPU the write was, but we know where the integrity check failed
    pIntViol->Header.CpuContext.Valid = FALSE;

    IntAlertFillVersionInfo(&pIntViol->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViol, sizeof(*pIntViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}

static BOOLEAN
IntWinTokenPrivsShouldHook(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD NewTokenPtr
    )
///
/// @brief Decides if the given token address should be hooked through EPT or not.
///
/// The decision is taken based on various considerations. If we have hardware support
/// for sub page protection, we will always hook the tokens through EPT, as the impact
/// will be much lower, even lower that with the "force allocation to page size" trick.
/// On static detected processes, most likely the token was allocated before. On dynamically
/// detected processes we will check if the token has been allocated with one page size,
/// in which case we will hook the given token through EPT.
///
/// @param[in]  Process The #WIN_PROCESS_OBJECT for which the token would be decided if it
///                     should be protected or not.
/// @param[in]  NewTokenPtr The given token pointer.
///
/// @retval     TRUE    If the given token pointer should be hooked through EPT for the
///                     privileges protection.
/// @retval     FALSE   If protecting the given token through EPT would induce a high
///                     performance impact.
///
{
    void *pPage = NULL;
    INTSTATUS status;
    const POOL_HEADER *ph;
    DWORD blockSize, desiredBlockSize;
    BOOLEAN ret;

    // By default protect everything through EPT if we have SPP.
    if (gGuest.SupportSPP)
    {
        return TRUE;
    }

    // If the process was static detected there's virtually no chance that the token was allocated
    // through our hook. Bail out the following checks since they would most likely not pass on static
    // detected processes.
    if (Process->StaticDetected)
    {
        return FALSE;
    }

    // The process is not static detected, now verify that the token is really allocated through our hook handler
    // and the allocation has been forced to PAGE_SIZE for performance improvement. If the block size is not 0xff
    // (meaning that the allocation + sizeof(pool_header) = 1 page), it means that the allocation was not forced
    // and we should not protect through EPT this token, as it would most probably induce a high performance impact.
    // We have previously observed this behavior on the "registry" process, where the token assigned to that process
    // is allocated at boot time, long before we initialize our hooks.
    status = IntVirtMemMap(NewTokenPtr & PAGE_MASK, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", NewTokenPtr, status);
        return FALSE;
    }

    ph = IntWinPoolGetPoolHeaderInPage(pPage, NewTokenPtr & PAGE_OFFSET, WIN_POOL_TAG_TOKE);
    if (NULL == ph)
    {
        // Try with WIN_POOL_TAG_TOKE2, as on windows 7, the most significant bit is set if the allocation is
        // considered "Protected".
        ph = IntWinPoolGetPoolHeaderInPage(pPage, NewTokenPtr & PAGE_OFFSET, WIN_POOL_TAG_TOKE2);
        if (NULL == ph)
        {
            ERROR("[ERROR] IntWinPoolGetPoolHeaderInPage did not found a valid pool header!\n");
            ret = FALSE;
            goto _exit;
        }
    }

    blockSize = gGuest.Guest64 ? ph->Header64.BlockSize : ph->Header32.BlockSize;
    desiredBlockSize = gGuest.Guest64 ? 0xFF : 0x1FF;

    if (blockSize != desiredBlockSize)
    {
        // This means that the token didn't go through our allocation hook. That's a pity, but we'll detect it through
        // integrity if anything goes wrong, or if the token changes to one of the tokens which were forced
        // to page size.
        ret = FALSE;
        goto _exit;
    }

    ret = TRUE;

_exit:
    if (NULL != pPage)
    {
        IntVirtMemUnmap(&pPage);
    }

    return ret;
}


static INTSTATUS
IntWinTokenProtectPrivsInternal(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD NewTokenPtr
    )
///
/// @brief If needed, this function will establish an EPT hook on the given token pointer for privileges protection.
/// Note that, this function might get called in the case where Process->OriginalTokenPtr != NewTokenPtr, in order
/// to re-establish the hook in the case where the token pointer has changed between timer ticks.
///
/// @param[in]  Process The process for which the token should be protected or not.
/// @param[in]  NewTokenPtr The address of the token for which the privileges would be protected.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (NULL != Process->TokenHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Process->TokenHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != Process->TokenSwapHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Process->TokenSwapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            return status;
        }
    }

    if (IntWinTokenPrivsShouldHook(Process, NewTokenPtr))
    {
        status = IntHookGvaSetHook(gGuest.Mm.SystemCr3,
                                   NewTokenPtr & PAGE_MASK,
                                   PAGE_SIZE,
                                   IG_EPT_HOOK_WRITE,
                                   IntWinTokenPrivsHandleWrite,
                                   Process,
                                   NULL,
                                   0,
                                   (HOOK_GVA **)&Process->TokenHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookGvaSetHook(gGuest.Mm.SystemCr3,
                                   NewTokenPtr & PAGE_MASK,
                                   PAGE_SIZE,
                                   IG_EPT_HOOK_NONE,
                                   IntWinTokenPrivsHandleSwap,
                                   Process,
                                   NULL,
                                   HOOK_FLG_HIGH_PRIORITY,
                                   (HOOK_GVA **)&Process->TokenSwapHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        TRACE("[INFO] Token at 0x%016llx is not allocated through our hook - we'll protect it only with integrity!\n",
              NewTokenPtr);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinTokenPrivsHandleSwap(
    _In_opt_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief Handles a token swap-in or swap-out, re-applying protection if the token is not assigned anymore to
///         a process.
/// When a token is de-allocated and the whole page becomes free, as we increased on ExAllocatePoolWithTag the
/// size of token allocations to always be one page, for performance purposes, the kernel may use the already
/// freed page for different purposes, sometimes even mapping new physical memory into it. Since we have already
/// hooked the page against writes, we will have, in such cases, translation violations, as the new mapping will
/// not have the same contents as the TOKEN allocation which was freed before. Therefore we have to verify during
/// the translation modifications of tokens if the current token is still assigned to the process and it was just
/// swapped out, or if it has been freed, in which case we should re-establish the hook on the newly assigned
/// token, while removing the old hook, which will solve the possibility of translation violations appearing
/// in this case.
///
/// @param[in]  Context         The page for which this handler is invoked.
/// @param[in]  VirtualAddress  The guest virtual address for which this handler is invoked.
/// @param[in]  OldEntry        The old page table entry used to translate VirtualAddress.
/// @param[in]  NewEntry        The new page table entry used to translate VirtualAddress.
/// @param[in]  OldPageSize     The old page size.
/// @param[in]  NewPageSize     The new page size.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *pProc = Context;
    QWORD newTokenPtr = 0;

    if (NULL == pProc)
    {
        return INT_STATUS_NOT_FOUND;
    }

    STATS_ENTER(statsTokenSwapCheck);

    status = IntKernVirtMemFetchWordSize(pProc->EprocessAddress + WIN_KM_FIELD(Process, Token), &newTokenPtr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);

        STATS_EXIT(statsTokenSwapCheck);

        return status;
    }

    newTokenPtr = EX_FAST_REF_TO_PTR(gGuest.Guest64, newTokenPtr);

    if (newTokenPtr != pProc->OriginalTokenPtr)
    {
        LOG("[INFO] Token has been changed during translation modification of 0x%016llx [0x%016llx -> 0x%016llx], "
            "[0x%016llx -> 0x%016llx]: old = 0x%016llx, new = 0x%016llx\n",
            VirtualAddress, OldEntry, NewEntry, OldPageSize, NewPageSize, pProc->OriginalTokenPtr, newTokenPtr);

        IntWinTokenProtectPrivsInternal(pProc, newTokenPtr);

        // Check integrity if token changed.
        IntWinTokenPtrCheckIntegrityOnProcess(pProc);
    }

    STATS_EXIT(statsTokenSwapCheck);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinTokenPrivsHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief EPT callback triggered when a write occurs over the Privileges bitfields in a nt!_TOKEN structure
/// protected through EPT.
///
/// @param[in]  Context The process for which the given nt!_TOKEN structure has been associated with.
/// @param[in]  Hook    The GPA_HOOK structure which was set on the given token.
/// @param[in]  Address The guest physical address on which the write took place.
/// @param[out] Action  The action decided by the engine for the current violation.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If a process is not given as Context.
///
{
    WIN_PROCESS_OBJECT *pProc = Context;
    QWORD newTokenPtr = 0;
    INTSTATUS status;
    INTRO_ACTION_REASON reason;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    BOOLEAN exitAfterInformation = FALSE;
    DWORD privsOffsetInPage, writeOffset;

    UNREFERENCED_PARAMETER(Hook);

    *Action = introGuestAllowed;

    if (NULL == pProc)
    {
        return INT_STATUS_NOT_FOUND;
    }

    STATS_ENTER(statsTokenChangeCheck);

    status = IntKernVirtMemFetchWordSize(pProc->EprocessAddress + WIN_KM_FIELD(Process, Token), &newTokenPtr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);

        STATS_EXIT(statsTokenChangeCheck);

        return status;
    }

    newTokenPtr = EX_FAST_REF_TO_PTR(gGuest.Guest64, newTokenPtr);

    if (newTokenPtr != pProc->OriginalTokenPtr)
    {
        IntWinTokenProtectPrivsInternal(pProc, newTokenPtr);

        // Check integrity if token changed.
        IntWinTokenPtrCheckIntegrityOnProcess(pProc);

        *Action = introGuestAllowed;
        STATS_EXIT(statsTokenChangeCheck);
        return INT_STATUS_SUCCESS;
    }

    STATS_EXIT(statsTokenChangeCheck);

    privsOffsetInPage = (pProc->OriginalTokenPtr & PAGE_OFFSET) + WIN_KM_FIELD(Token, Privs);
    writeOffset = Address & PAGE_OFFSET;

    // The write [woff, woff + access_size) was outside the ranges [privoff, privoff + 3 * sizeof(QWORD)),
    // basically the interval [a, b) cannot intersect with [x, y) if either b <= x or a >= y. Since we already verified
    // if the token has changed, and the write is not over the Privileges field, we will just return in this case.
    if (writeOffset + gVcpu->AccessSize <= privsOffsetInPage || writeOffset >= privsOffsetInPage + 3 * sizeof(QWORD))
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsTokenWrites);
    STATS_ENTER(statsExceptionsKern);

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(Context,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeTokenPrivs,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        goto _exit_exceptions;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

_exit_exceptions:
    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_TOKEN_PRIVS, Action, &reason))
    {
        IntWinTokenPrivsSendEptAlert(&originator, &victim, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_TOKEN_PRIVS, Action);

    STATS_EXIT(statsTokenWrites);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinTokenFetchTokenAddress(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ QWORD *OldValue,
    _Out_ QWORD *NewValue
    )
///
/// @brief Fetches the token pointer from inside the EPROCESS and returns the old token pointer and the new token
/// pointer which may have changed at the time of the read.
///
/// Note: the returned old value and new value can be the same, one should check those value after calling this function
/// in order to ensure that the token pointer has changed. If the change is considered alright, one should update
/// Process->OriginalTokenPtr after calling this function.
///
/// @param[in]  Process     The #WIN_PROCESS_OBJECT for which new token should be fetched.
/// @param[out] OldValue    The old token pointer, stored internally in OriginalTokenPtr field of #WIN_PROCESS_OBJECT.
/// @param[out] NewValue    The value fetched from the Token field of the given EPROCESS inside the guest.
///
/// @retval #INT_STATUS_SUCCESS             On success.
/// @retval #INT_STATUS_PAGE_NOT_PRESENT    If the eprocess is not present in memory and the token cannot be read.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr = { 0 };
    QWORD newValue = 0, oldValue = 0;

    status = IntTranslateVirtualAddressEx(Process->EprocessAddress + WIN_KM_FIELD(Process, Token),
                                          gGuest.Mm.SystemCr3,
                                          TRFLG_PG_MODE,
                                          &tr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return status;
    }

    if (0 == (tr.Flags & PT_P))
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    // Read the token.
    status = IntGpaCacheFetchAndAdd(gGuest.GpaCache, tr.PhysicalAddress, gGuest.WordSize, (PBYTE)&newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed: 0x%08x\n", status);
        return status;
    }

    // Ignore ref count.
    newValue = EX_FAST_REF_TO_PTR(gGuest.Guest64, newValue);
    oldValue = EX_FAST_REF_TO_PTR(gGuest.Guest64, Process->OriginalTokenPtr);

    *OldValue = oldValue;
    *NewValue = newValue;

    return INT_STATUS_SUCCESS;
}


_Success_(return == TRUE)
BOOLEAN
IntWinTokenPtrIsStolen(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BOOLEAN Check,
    _Out_opt_ WIN_PROCESS_OBJECT **FromProcess,
    _Out_opt_ QWORD *OldValue,
    _Out_opt_ QWORD *NewValue
    )
///
/// @brief      This function checks if the security token of a given process has been stone from another process.
///
/// @param[in]  Process         The process who`s token has to be verified.
/// @param[in]  Check           If TRUE, #gWinProcesses will be iterated to see if the token value is
///                             the same for another process (same thing happens if the original token pointer
///                             has been modified).
/// @param[out] FromProcess     The process where the token has been stolen from.
/// @param[out] OldValue        The old token.
/// @param[out] NewValue        The new token.
///
/// @retval     #TRUE       The given process has a stolen token.
/// @retval     #FALSE      The given process has its original token.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD newValue = 0, oldValue = 0;
    WIN_PROCESS_OBJECT *pProc = Process;

    status = IntWinTokenFetchTokenAddress(pProc, &oldValue, &newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinTokenFetchTokenAddress failed: 0x%08x\n", status);
        return FALSE;
    }

    pProc->OriginalTokenPtr = newValue;

    // the pointer should never change
    if (Check || ((newValue != oldValue) && (0 != newValue)))
    {
        WIN_PROCESS_OBJECT* pProc2 = NULL;
        LIST_ENTRY* list;
        BOOLEAN bFound;

        // Check if the new token belongs to another process; if it doesn't, we can bail out, it is most likely
        // a legitimate action.
        bFound = FALSE;
        list = gWinProcesses.Flink;
        while (list != &gWinProcesses)
        {
            pProc2 = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

            list = list->Flink;

            // Ignore the current process, as it will obviously have this token already.
            if (pProc2 == pProc)
            {
                continue;
            }

            if (EX_FAST_REF_TO_PTR(gGuest.Guest64, pProc2->OriginalTokenPtr) == newValue)
            {
                bFound = TRUE;
                break;
            }
        }

        if (!bFound || (NULL == pProc2))
        {
            goto _bail_out;
        }

        if (NULL != NewValue)
        {
            *NewValue = newValue;
        }

        if (NULL != OldValue)
        {
            *OldValue = oldValue;
        }

        if (NULL != FromProcess)
        {
            *FromProcess = pProc2;
        }

        return TRUE;
    }

_bail_out:
    return FALSE;
}


INTSTATUS
IntWinTokenPtrCheckIntegrityOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
)
///
/// @brief      This function checks if the security token of a given process has been stone from another process.
///
/// @param[in]  Process         The process whose token has to be verified.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    QWORD newValue;
    QWORD oldValue;
    WIN_PROCESS_OBJECT *pProc;
    WIN_PROCESS_OBJECT *pProc2;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pProc = Process;

    if (IntWinTokenPtrIsStolen(pProc, FALSE, &pProc2, &oldValue, &newValue))
    {
        EVENT_INTEGRITY_VIOLATION* pIntViolation;
        INTSTATUS status;

        IntPauseVcpus();

        LOG("[INTEGRITY VIOLATION] Token pointer was modified (%llx -> %llx): "
            "process %llx (%d / %s), token stolen from process %llx (%d / %s)\n",
            oldValue, newValue, pProc->EprocessAddress, pProc->Pid,
            pProc->Name, pProc2->EprocessAddress, pProc2->Pid, pProc2->Name);
        if (gGuest.KernelBetaDetections)
        {
            LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (B) MALWARE ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
        }
        else
        {
            LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
        }

        // We can't change the pointer back to the original value because that would result in a bug check
        // almost all the time so save the new value in order to avoid alert spamming and to catch future changes.

        pIntViolation = &gAlert.Integrity;
        memzero(pIntViolation, sizeof(*pIntViolation));

        pIntViolation->Header.Action = introGuestAllowed;
        pIntViolation->Header.Reason = introReasonNoException;
        pIntViolation->Header.MitreID = idAccessToken;

        pIntViolation->Header.CpuContext.Valid = FALSE;

        IntAlertFillWinProcess(pProc, &pIntViolation->Header.CurrentProcess);
        IntAlertFillWinProcess(pProc, &pIntViolation->Originator.Process);
        IntAlertFillWinProcess(pProc2, &pIntViolation->Victim.Process);

        if (gGuest.KernelBetaDetections)
        {
            pIntViolation->Header.Flags |= ALERT_FLAG_BETA;
        }
        pIntViolation->Header.Flags |= ALERT_FLAG_ASYNC;

        pIntViolation->Victim.Type = introObjectTypeTokenPtr;
        memcpy(pIntViolation->Victim.Name, VICTIM_PROCESS_TOKEN, sizeof(VICTIM_PROCESS_TOKEN));

        pIntViolation->Size = gGuest.WordSize;
        pIntViolation->BaseAddress = pProc2->EprocessAddress + WIN_KM_FIELD(Process, Token);
        pIntViolation->VirtualAddress = pProc->EprocessAddress + WIN_KM_FIELD(Process, Token);

        pIntViolation->WriteInfo.Size = gGuest.WordSize;
        pIntViolation->WriteInfo.OldValue[0] = oldValue;
        pIntViolation->WriteInfo.NewValue[0] = newValue;

        IntAlertFillVersionInfo(&pIntViolation->Header);

        status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViolation, sizeof(*pIntViolation));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinTokenCheckCurrentPrivileges(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD TokenPtr,
    _In_ BOOLEAN IntegrityCheck,
    _Out_ BOOLEAN *PresentIncreased,
    _Out_ BOOLEAN *EnabledIncreased,
    _Out_opt_ QWORD *Present,
    _Out_opt_ QWORD *Enabled
    )
///
/// @brief Verifies the current token if the current Privileges.Present and Privileges.Enabled fields were
/// not altered in a malicious way.
///
/// The checks performed on integrity on privileges are:
/// 1. The Present field inside Privileges should not increase. That means, no bits should be 1 if they were
/// previously 0. Note that present privileges may decrease.
/// 2. Any bit set in the Enabled field of Privileges should also be set in the Present field. As the kernel checks
/// against the Present bitfield when increasing a privilege in the Enabled bitfield, but when checking the privileges
/// before accessing a resource, the kernel only checks the Enabled bitfield, we should ensure that there is a
/// consistency between those fields.
/// Note: This function might be called in cases where Process->OriginalTokenPtr != TokenPtr (e.g. the current token
/// assigned to the given process has changed, but we have not yet updated Process->OriginalTokenPtr internally), when
/// it is not this case, one might simply call this function with Process->OriginalTokenPtr as the second argument.
///
/// @param[in]  Process             The process for which the checks are done.
/// @param[in]  TokenPtr            The GVA which points to the assigned token, may be different from
///                                 Process->OriginalTokenPtr.
/// @param[in]  IntegrityCheck      This should be set by the caller if this function is called during an integrity check
///                                 on timer. If this parameter is set, the function will take into account the corner case
///                                 in which there is a one bit difference between Enabled and Present privileges, due to
///                                 a race condition between our checks and the privilege removal from the guest.
/// @param[out] PresentIncreased    It will store a boolean representing whether the current privileges violate the
///                                 first check.
/// @param[out] EnabledIncreased    It will store a boolean representing whether the current privileges violate the
///                                 second check.
/// @param[out] Present The current value in the Privileges.Present field.
/// @param[out] Enabled The current value in the Privileges.Enabled field.
///
/// @retval #INT_STATUS_SUCCESS             On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1 If a NULL Process has been given.
/// @retval #INT_STATUS_INVALID_PARAMETER_3 If a NULL PresentIncreased has been given.
/// @retval #INT_STATUS_INVALID_PARAMETER_4 If a NULL EnabledIncreased has been given.
///
{
    INTSTATUS status;
    QWORD privs[2];
    QWORD present, enabled;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == PresentIncreased)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == EnabledIncreased)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *PresentIncreased = FALSE;
    *EnabledIncreased = FALSE;

    // Always check the new token, as the old token may have been used for something else in the meantime.
    status = IntVirtMemRead(TokenPtr + WIN_KM_FIELD(Token, Privs), 2 * sizeof(QWORD), gGuest.Mm.SystemCr3, privs, NULL);
    if (!INT_SUCCESS(status))
    {
        // The token is probably not present in memory, nothing we can do for now...
        return status;
    }

    present = privs[0];
    enabled = privs[1];

    // We might have not fetched the enabled/present beforehand, so don't bother checking.
    if (Process->OriginalEnabledPrivs == 0 && Process->OriginalPresentPrivs == 0)
    {
        goto _skip_checks;
    }

    // Check if there is any bit which is set in present and not set in original present.
    if ((present & (~Process->OriginalPresentPrivs)) != 0)
    {
        *PresentIncreased = TRUE;
    }

    // All bits in enabled must also be set in present, if any bit is not set in present => it shouldn't
    // have that privilege. Note that if we previously didn't give a detection due to the fact that only one bit was
    // changed, we will give a detection now if there is any bit which is set in enabled but not set in present.
    if ((enabled != Process->OriginalEnabledPrivs || (Process->PrivsChangeOneBit && IntegrityCheck)) &&
        (enabled & present) != enabled)
    {
        // Some versions of Windows are special and, when a privilege is disabled, it disables it from present and
        // just after that from enabled. This may lead to a race condition, where we find a bit in Enabled
        // which is not set in Present. We will check a bit which can give a detection in this case, and skip the
        // detection if this happens. Note that we will do it only once and only on integrity. We expect that, at
        // next check the 1-bit difference to not be present anymore, as it would indicate malicious behavior, and
        // not the presented race condition.
        if (!Process->PrivsChangeOneBit && IntegrityCheck)
        {
            QWORD diffbits = enabled & (~(enabled & present));

            if (diffbits != 0 && (diffbits & (diffbits - 1)) == 0)
            {
                WARNING("[WARNING] Special case on OS version: %d, difference 1 bit! 0x%016llx 0x%016llx\n",
                        gGuest.OSVersion, enabled, present);

                Process->PrivsChangeOneBit = TRUE;

                goto _skip_checks;
            }
        }

        // Since we're giving a detection, we'll reset the flag, but only if we are doing an integrity check.
        if (IntegrityCheck)
        {
            Process->PrivsChangeOneBit = FALSE;
        }

        *EnabledIncreased = TRUE;
    }
    else if (IntegrityCheck)
    {
        // Since there seems nothing have changed in a malicious way, we'll reset the flag, but only if we
        // are doing an integrity check.
        Process->PrivsChangeOneBit = FALSE;
    }

_skip_checks:
    if (NULL != Present)
    {
        *Present = present;
    }

    if (NULL != Enabled)
    {
        *Enabled = enabled;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinTokenPrivsCheckIntegrityOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief This function checks if the privileges bitfields for the given process have been changed in a malicious
/// manner, sending an alert if needed.
///
/// @param[in]  Process The #WIN_PROCESS_OBJECT for which the privileges are checked in the assigned token.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD present, enabled;
    QWORD oldValue = 0, newValue = 0;
    BOOLEAN presentIncreased = FALSE, enabledIncreased = FALSE;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntWinTokenFetchTokenAddress(Process, &oldValue, &newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinTokenFetchTokenAddress failed: 0x%08x!\n", status);
        return status;
    }

    if (oldValue != newValue)
    {
        IntWinTokenProtectPrivsInternal(Process, newValue);
    }

    status = IntWinTokenCheckCurrentPrivileges(Process,
                                               newValue,
                                               TRUE,
                                               &presentIncreased,
                                               &enabledIncreased,
                                               &present,
                                               &enabled);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (Process->SkipPrivsNextCheck)
    {
        goto _skip_checks;
    }

    if (presentIncreased || enabledIncreased)
    {
        STATS_ENTER(statsExceptionsKern);

        // The originator is only dummy. Complete just the elements so that we can go through exceptions.
        originator.Original.NameHash = INITIAL_CRC_VALUE;
        originator.Return.NameHash = INITIAL_CRC_VALUE;

        // Since we don't have an INTEGRITY_REGION associated, we'll complete the victim in-place.
        victim.Object.Process = Process;
        victim.Object.NameHash = Process->NameHash;
        victim.Object.Type = introObjectTypeTokenPrivs;
        victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
        victim.ZoneType = exceptionZoneIntegrity;

        victim.WriteInfo.OldValue[0] = Process->OriginalPresentPrivs;
        victim.WriteInfo.OldValue[1] = Process->OriginalEnabledPrivs;

        victim.WriteInfo.NewValue[0] = present;
        victim.WriteInfo.NewValue[1] = enabled;

        victim.WriteInfo.AccessSize = 2 * sizeof(QWORD);

        IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

        STATS_EXIT(statsExceptionsKern);

        if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_TOKEN_PRIVS, &action, &reason))
        {
            // Mark action as allowed, since we didn't really block anything.
            IntWinTokenPrivsSendIntegrityAlert(&victim, introGuestAllowed, reason);

            if (presentIncreased)
            {
                WARNING("[WARNING] Present privileges are higher than the original ones: "
                        "0x%016llx vs 0x%016llx in process %s:%d\n",
                        present,
                        Process->OriginalPresentPrivs,
                        Process->Name,
                        Process->Pid);
            }
            if (enabledIncreased)
            {
                WARNING("[WARNING] Enabled privileges are higher than the present ones: "
                        "0x%016llx vs 0x%016llx in process %s:%d\n",
                        enabled,
                        present,
                        Process->Name,
                        Process->Pid);
            }
        }

        // Theoretically, we can overwrite the privileges with the old ones if not allowed, but note that we are
        // around ~1 sec after the LPE took place, so the exploit could have run enough to do damage
        // with the gained privileges, so there's not much to do about it...

        // Note that we should also consider on DPI from now on as a detection every process creation, since
        // on DPI we will see only the changed values, as we update them below.
        // NOTE: we set the DPI flag only if Present privileges were increased. If Enabled were increased in
        // comparison with Present, then the DPI mechanism will issue an alert as is, as the heuristic will
        // detect the Enabled extra bits at that point. However, if Present privileges were increased, we won't 
        // be able to detect it otherwise. Also, after Present privileges increase has taken place, we can't
        // consider any process creation as legitimate in DPI from now on, as we can't know in a reliable way
        // when Present privileges will be ok in the future, so we won't mark PrivsChangeDetected as FALSE at
        // any point from now on.
        if (presentIncreased)
        {
            Process->PrivsChangeDetected = TRUE;
        }
    }

_skip_checks:
    // Save them so we don't give an alert for the same stuff once every second.
    Process->OriginalPresentPrivs = present;
    Process->OriginalEnabledPrivs = enabled;

    // On the next tick, give a detection if something else changed.
    Process->SkipPrivsNextCheck = FALSE;

    return status;
}


TIMER_FRIENDLY INTSTATUS
IntWinTokenCheckIntegrity(
    void
    )
///
/// @brief      This function checks the integrity of the security token for all the processes inside #gWinProcesses.
/// The checks include both verifying if there are token pointers belonging to multiple processes, indicating a stolen
/// token, and verifying if the Token Privileges have not changed in a malicious way, indicating a privilege escalation.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    LIST_ENTRY *pList = NULL;

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (0 == (gGuest.CoreOptions.Current & (INTRO_OPT_PROT_KM_TOKEN_PTR | INTRO_OPT_PROT_KM_TOKEN_PRIVS))))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pList = gWinProcesses.Flink;
    while (pList != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT* pProcess = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);
        INTSTATUS status;

        pList = pList->Flink;

        // Note: the order is important here, we should do the token stolen integrity checks
        // always the last one, since afterwards we won't have anymore the old token, as the
        // check will also overwrite the OriginalTokenPtr field.
        if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS))
        {
            status = IntWinTokenPrivsCheckIntegrityOnProcess(pProcess);
            if (!INT_SUCCESS(status) &&
                INT_STATUS_PAGE_NOT_PRESENT != status && INT_STATUS_NO_MAPPING_STRUCTURES != status)
            {
                ERROR("[ERROR] IntWinTokenPtrCheckIntegrityOnProcess failed: 0x%08x\n", status);
            }
        }

        if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PTR))
        {
            status = IntWinTokenPtrCheckIntegrityOnProcess(pProcess);
            if (!INT_SUCCESS(status) &&
                INT_STATUS_PAGE_NOT_PRESENT != status && INT_STATUS_NO_MAPPING_STRUCTURES != status)
            {
                ERROR("[ERROR] IntWinTokenPtrCheckIntegrityOnProcess failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinTokenPrivsProtectOnProcess(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief Updates the stored original Privileges bitfields (Present and Enabled) and hooks through EPT the Privileges
/// inside the assigned token of the given process, if needed.
///
/// @param[in, out] Process The #WIN_PROCESS_OBJECT for which the privileges information is stored, and for which
///                         a hook would be established on the assigned token, if needed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1 If the given process is NULL.
///
{
    QWORD privs[2];
    INTSTATUS status;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != Process->TokenHook)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntVirtMemRead(Process->OriginalTokenPtr + WIN_KM_FIELD(Token, Privs),
                            2 * sizeof(QWORD),
                            gGuest.Mm.SystemCr3,
                            privs,
                            NULL);
    if (!INT_SUCCESS(status))
    {
        // If the page is not present, just skip checks on next integrity and skip ept hooking,
        // as we can't properly decide whether to hook the token or not.
        if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
        {
            Process->SkipPrivsNextCheck = TRUE;
            return INT_STATUS_SUCCESS;
        }

        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    // Save them even if the flag was not given, so that, if the flag is suddenly activated and we check integrity,
    // we won't have any bad surprises.
    Process->OriginalPresentPrivs = privs[0];
    Process->OriginalEnabledPrivs = privs[1];

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return IntWinTokenProtectPrivsInternal(Process, Process->OriginalTokenPtr);
}


INTSTATUS
IntWinTokenPrivsUnprotectOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    )
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != Process->TokenHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Process->TokenHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }
    }

    if (NULL != Process->TokenSwapHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Process->TokenSwapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }
    }

    return status;
}


INTSTATUS
IntWinTokenProtectPrivs(
    void
    )
///
/// @brief Protects all the currently unprotected tokens belonging to processes against privileges manipulation.
///
/// @retval #INT_STATUS_SUCCESS         On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the option #INTRO_OPT_PROT_KM_TOKEN_PRIVS is not activated.
///
{
    LIST_ENTRY *list;
    INTSTATUS status;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    list = gWinProcesses.Flink;

    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT* pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        status = IntWinTokenPrivsProtectOnProcess(pProc);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinTokenPrivsProtectOnProcess failed for %s:%d: 0x%08x\n",
                    pProc->Name,
                    pProc->Pid,
                    status);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinTokenUnprotectPrivs(
    void
    )
///
/// @brief Unprotects all the currently protected tokens belonging to processes against privileges manipulation.
///
/// @retval #INT_STATUS_SUCCESS         On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the option #INTRO_OPT_PROT_KM_TOKEN_PRIVS is in fact activated.
///
{
    LIST_ENTRY *list;
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    list = gWinProcesses.Flink;

    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT* pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        if (NULL != pProc->TokenHook)
        {
            IntHookGvaRemoveHook((HOOK_GVA **)&pProc->TokenHook, 0);
        }

        if (NULL != pProc->TokenSwapHook)
        {
            IntHookGvaRemoveHook((HOOK_GVA **)&pProc->TokenSwapHook, 0);
        }
    }

    return status;
}
