/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winthread.h"
#include "alerts.h"
#include "crc32.h"
#include "guests.h"
#include "winpe.h"
#include "winprocesshp.h"

///
/// @file winthread.c
///
/// @brief This file implements Windows Threads related functionality (obtaining thread information, blocking thread
/// hijacking and APC injections).
///
/// In order to protect Windows Threads, introcore places some hooks (see winhkhnd.c) on functions such as
/// "PspSetContextThreadInternal" (a thread context has been modified) or "NtQueueApcThreadEx" (and APC has
/// been queued) in order to block process injection attempts. This file also provides general use, thread related
/// functionality such as obtaining the current thread (given a CPU) - #IntWinThrGetCurrentThread.
///


INTSTATUS
IntWinThrGetCurrentThread(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *EthreadAddress
    )
///
/// @brief      Get the ETHREAD structure address of the thread currently running on the given CPU.
///
/// This function assumes that it is called while the guest is in kernel mode. Also, this only works for the current
/// CPU or if the requested CPU is paused.
///
/// @param[in]  CpuNumber           The CPU number to get the running thread for (it can be #IG_CURRENT_VCPU).
/// @param[out] EthreadAddress      The ETRHEAD structure address of the running thread.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   KPCR (Kernel Processor Control Region) was not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == EthreadAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (CpuNumber == IG_CURRENT_VCPU)
    {
        CpuNumber = IntGetCurrentCpu();
    }

    if (CpuNumber >= gGuest.CpuCount)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    *EthreadAddress = 0;

    if (0 == gGuest.VcpuArray[CpuNumber].PcrGla)
    {
        status = IntFindKernelPcr(CpuNumber, &gGuest.VcpuArray[CpuNumber].PcrGla);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntFindKernelPcr failed: 0x%08x\n", status);
            return status;
        }
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, gGuest.VcpuArray[CpuNumber].PcrGla))
    {
        TRACE("[CPU %d] Could not find a kernel KPCR, will not cache anything: 0x%016llx\n",
              CpuNumber, gGuest.VcpuArray[CpuNumber].PcrGla);
        gGuest.VcpuArray[CpuNumber].PcrGla = 0;

        return INT_STATUS_NOT_FOUND;
    }

    status = IntKernVirtMemRead(gGuest.VcpuArray[CpuNumber].PcrGla + WIN_KM_FIELD(Pcr, CurrentThread),
                                gGuest.WordSize, EthreadAddress, NULL);

    return status;
}


///
/// @brief  The maximum number of threads for one single process (if something happens, #IntWinThrIterateThreads will
/// NOT loop indefinitely).
///
#define THREADS_MAX_COUNT           65536


INTSTATUS
IntWinThrIterateThreads(
    _In_ QWORD Eprocess,
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief      Iterate all the threads of the given process and invoke the callback for each one of them,
/// while passing the auxiliary value as a parameter.
///
/// @param[in]  Eprocess    The EPROCESS address of the process to iterate the threads for.
/// @param[in]  Callback    The callback to be invoked for each thread.
/// @param[in]  Aux         The auxiliary value to be passed as a parameter to the callback function (can be NULL).
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_SUPPORTED   There were more than #THREADS_MAX_COUNT threads (this should not happen).
///
{
    INTSTATUS status;
    QWORD currentThread = 0, count;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    count = 0;

    status = IntKernVirtMemFetchWordSize(Eprocess + WIN_KM_FIELD(Process, ThreadListHead), &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for VA 0x%016llx: 0x%08x\n", Eprocess, status);
        return status;
    }

    // parse the threads and show their addresses for now
    while ((currentThread != Eprocess + WIN_KM_FIELD(Process, ThreadListHead)) &&
           (count++ < THREADS_MAX_COUNT))
    {
        QWORD ethreadAddress;

        ethreadAddress = currentThread - WIN_KM_FIELD(Thread, ThreadListEntry);

        status = Callback(ethreadAddress, Aux);
        if (INT_STATUS_BREAK_ITERATION == status)
        {
            status = INT_STATUS_SUCCESS;
            goto _cleanup_and_exit;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Callback failed for thread 0x%016llx, proc 0x%016llx: 0x%08x\n",
                  ethreadAddress, Eprocess, status);
        }

        status = IntKernVirtMemFetchWordSize(currentThread, &currentThread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the next thread: 0x%08x\n", status);
            break;
        }
    }

_cleanup_and_exit:

    if (count >= THREADS_MAX_COUNT)
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntWinThrGetCurrentTib(
    _In_ IG_CS_RING CurrentRing,
    _In_ IG_CS_TYPE CsType,
    _Out_ QWORD *Tib
    )
///
/// @brief      Obtain the TIB (Thread Information Block) of the thread running on the current CPU.
///
/// @param[in]  CurrentRing     The current execution ring.
/// @param[in]  CsType          The code segment type.
/// @param[out] Tib             The TIB address.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2     A 64 bit code segment was provided but the guest is NOT 64 bit
///                                                 based.
///
/// @retval     #INT_STATUS_INVALID_PARAMETER_3     The provided Tib parameter is NULL.
///
{
    INTSTATUS status;

    if (NULL == Tib)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    *Tib = 0;

    if (IG_CS_TYPE_64B == CsType && !gGuest.Guest64)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CS_RING_3 == CurrentRing)
    {
        // User mode context, simply read FS/GS
        if (IG_CS_TYPE_64B == CsType)
        {
            status = IntGsRead(IG_CURRENT_VCPU, Tib);
        }
        else
        {
            status = IntFsRead(IG_CURRENT_VCPU, Tib);
        }
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGs/FsRead failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        // Kernel mode context
        if (IG_CS_TYPE_32B == CsType && gGuest.Guest64)
        {
            // 32-bit thread on 64-bit system, simply read FS
            status = IntFsRead(IG_CURRENT_VCPU, Tib);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGsRead failed: 0x%08x\n", status);
                return status;
            }
        }
        else
        {
            // 32-bit thread on 32-bit system, or 64-bit thread on 64-bit system, we need to read it from the KTHREAD
            QWORD currentEthread = 0;
            status = IntWinThrGetCurrentThread(gVcpu->Index, &currentEthread);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
                return status;
            }

            status = IntKernVirtMemRead(currentEthread + WIN_KM_FIELD(Thread, Teb), gGuest.WordSize, Tib, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n",
                      currentEthread + WIN_KM_FIELD(Thread, Teb), status);
                return status;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinThrGetUmStackBaseAndLimitFromTib(
    _In_ QWORD Tib,
    _In_ IG_CS_TYPE CsType,
    _In_ QWORD Cr3,
    _Out_ QWORD *StackBase,
    _Out_ QWORD *StackLimit
    )
///
/// @brief      Obtains the user mode stack base and stack limit values.
///
/// @param[in]  Tib             The TIB address of the thread to get the stack base and limit for.
/// @param[in]  CsType          The code segment type.
/// @param[in]  Cr3             The address space.
/// @param[out] StackBase       The stack base.
/// @param[out] StackLimit      The stack limit.
///
/// @retval     #INT_STATUS_SUCCESS                     On success.
///
{
    const DWORD size = IG_CS_TYPE_64B == CsType ? 8 : 4;
    INTSTATUS status;
    QWORD buffer[2] = { 0 };

    if (NULL == StackBase)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == StackLimit)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    // Read the stack base & limit. They are at offset 4 on 32 bit on 8 on 64 bit.
    status = IntVirtMemRead(Tib + size, size * 2, Cr3, buffer, NULL);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) ||
        (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        return status;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    if (4 == size)
    {
        *StackBase = ((DWORD *)&buffer)[0];
        *StackLimit = ((DWORD *)&buffer)[1];
    }
    else
    {
        *StackBase = buffer[0];
        *StackLimit = buffer[1];
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinThrGetCurrentStackBaseAndLimit(
    _Out_ QWORD *TibBase,
    _Out_ QWORD *StackBase,
    _Out_ QWORD *StackLimit
    )
///
/// @brief      Obtains the stack base, stack limit and TIB address of the current thread.
///
/// @param[out] TibBase         The TIB address of the thread running on the current CPU.
/// @param[out] StackBase       The stack base of the thread running on the current CPU.
/// @param[out] StackLimit      The stack limit of the thread running on the current CPU.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_FOUND       The TIB was not found.
///
{
    INTSTATUS status;
    QWORD tibBase, buffer[2] = { 0 };
    DWORD csType;
    IG_ARCH_REGS regs;
    BYTE size;
    DWORD ring;

    if (NULL == TibBase)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == StackBase)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == StackLimit)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    tibBase = 0;
    csType = 0;

    status = IntGetGprs(IG_CURRENT_VCPU, &regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        return status;
    }

    // Get the CS type for this CPU (we need it in order to see if it's in 16 bit, 32 bit or 64 bit).
    status = IntGetCurrentMode(gVcpu->Index, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    status = IntGetCurrentRing(gVcpu->Index, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    size = csType == IG_CS_TYPE_64B ? 8 : 4;

    status = IntWinThrGetCurrentTib(ring, csType, &tibBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentTib failed: 0x%08x\n", status);
        return status;
    }

    *TibBase = tibBase;

    if (0 == tibBase)
    {
        ERROR("[ERROR] TIB base is 0!\n");
        return INT_STATUS_NOT_FOUND;
    }

    // Read the stack base & limit. They are at offset 4 on 32 bit on 8 on 64 bit.
    status = IntVirtMemRead(tibBase + size, size * 2, regs.Cr3, buffer, NULL);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        return status;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    if (4 == size)
    {
        *StackBase = ((DWORD *)&buffer)[0];
        *StackLimit = ((DWORD *)&buffer)[1];
    }
    else
    {
        *StackBase = buffer[0];
        *StackLimit = buffer[1];
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinThrHandleThreadHijack(
    _In_ void *Detour
    )
///
/// @brief      Handles a SetContextThread call - blocking thread hijacking.
/// @ingroup    group_detours
///
/// Thread hijacking (amongst others) is an approach to the process injection attack technique which allows an attacker
/// to execute arbitrary code in the context of another process. An attacker would achieve this by opening a victim
/// process, writing some malicious code to its memory, pausing a running thread and modifying the thread\`s execution
/// context so that it will run the malicious code after the thread`s execution is resumed.
/// If #PROC_OPT_PROT_SET_THREAD_CTX is set, this detour handler will block malicious SetContextThread calls
/// and send an alert.
///
/// @param[in]  Detour         The detour.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS regs;
    QWORD kthreadOriginator, eprocessOriginator;
    QWORD kthreadVictim, eprocessVictim;
    QWORD dstAddress, rip;
    QWORD args[2];
    PWIN_PROCESS_OBJECT pProcOrig, pProcVictim;
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    union
    {
        CONTEXT64 threadContext64;
        CONTEXT32 threadContext32;
    } threadContext = { 0 };
    BOOLEAN bIsDumpValid = TRUE;

    UNREFERENCED_PARAMETER(Detour);

    eprocessOriginator = eprocessVictim = kthreadVictim = dstAddress = rip = 0;
    pProcOrig = pProcVictim = NULL;
    action = introGuestAllowed;
    reason = introReasonUnknown;
    regs = &gVcpu->Regs;

    kthreadOriginator = regs->Rax;

    status = IntDetGetArguments(Detour, 2, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        goto cleanup_and_exit;
    }

    kthreadVictim = args[0];
    dstAddress = args[1];

    eprocessOriginator = kthreadOriginator + WIN_KM_FIELD(Thread, Process);

    status = IntKernVirtMemRead(eprocessOriginator, gGuest.WordSize, &eprocessOriginator, NULL);
    if (!INT_SUCCESS(status))
    {
        LOG("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", eprocessOriginator, status);
        reason = introReasonInternalError;
        goto cleanup_and_exit;
    }

    pProcOrig = IntWinProcFindObjectByEprocess(eprocessOriginator);
    if (pProcOrig == NULL)
    {
        ERROR("[ERROR] Failed to find originator with eprocess: %llx\n", eprocessOriginator);
        reason = introReasonInternalError;
        goto cleanup_and_exit;
    }

    eprocessVictim = kthreadVictim + WIN_KM_FIELD(Thread, Process);

    status = IntKernVirtMemRead(eprocessVictim, gGuest.WordSize, &eprocessVictim, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", eprocessVictim, status);
        reason = introReasonInternalError;
        goto cleanup_and_exit;
    }

    pProcVictim = IntWinProcFindObjectByEprocess(eprocessVictim);
    if (pProcVictim == NULL)
    {
        ERROR("[ERROR] Failed to find victim with eprocess: %llx\n", eprocessVictim);
        reason = introReasonInternalError;
        goto cleanup_and_exit;
    }

    if (pProcOrig->EprocessAddress == pProcVictim->EprocessAddress)
    {
        TRACE("[THREAD HIJACK] Hijack detected in same process, will allow...\n");
        reason = introReasonAllowed;
        goto cleanup_and_exit;
    }

    if (!pProcVictim->Protected || !pProcVictim->ProtThreadCtx)
    {
        reason = introReasonAllowed;
        goto cleanup_and_exit;
    }

    if (gGuest.Guest64 && !pProcOrig->Wow64Process)
    {
        memzero(&threadContext.threadContext64, sizeof(CONTEXT64));

        status = IntVirtMemRead(dstAddress, sizeof(CONTEXT64), pProcOrig->Cr3, &threadContext.threadContext64, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed for %llx: 0x%08x\n", dstAddress, status);
            bIsDumpValid = FALSE;
        }

        rip = threadContext.threadContext64.Rip;
    }
    else
    {
        memzero(&threadContext.threadContext32, sizeof(CONTEXT32));

        status = IntVirtMemRead(dstAddress, sizeof(CONTEXT32), pProcOrig->Cr3, &threadContext.threadContext32, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed for %llx: 0x%08x\n", dstAddress, status);
            bIsDumpValid = FALSE;
        }

        rip = threadContext.threadContext32.Eip;
    }

    STATS_ENTER(statsExceptionsUser);

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    status = IntExceptUserGetOriginator(pProcOrig, FALSE, 0, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptUserGetOriginator failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        action = introGuestNotAllowed;
        goto send_notification;
    }

    // We put length 1 because of the following reason: on SetContextThread injections the length of the "injected"
    // buffer should be 0 but 0 won't match on delta exports checks (it will check RVA + length - 1 > delta), and it
    // will not match as it is a comparison of 2 DWORDS, so we put 1 as a "dummy" access size so that we avoid this
    // problem.
    status = IntExceptGetVictimProcess(pProcVictim, rip, 1, ZONE_PROC_THREAD_CTX | ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetModifiedProcess failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        action = introGuestNotAllowed;
        goto send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_SET_THREAD_CTX, pProcVictim, &action, &reason))
    {
        EVENT_MEMCOPY_VIOLATION *pInjEvent = &gAlert.Injection;

        memzero(pInjEvent, sizeof(*pInjEvent));

        LOG("[THREAD HIJACK] Thread Hijack detected from KTHREAD: %llx, Process `%s` (pid = %d) into KTHREAD: "
            "%llx from Process `%s` (pid = %d)\n",
            kthreadOriginator, pProcOrig->Name, pProcOrig->Pid, kthreadVictim, pProcVictim->Name, pProcVictim->Pid);

        if (gGuest.Guest64 && !pProcOrig->Wow64Process)
        {
            if (!bIsDumpValid)
            {
                pInjEvent->DumpValid = FALSE;
            }
            else
            {
                LOG("Dumping CONTEXT registers %llx...", dstAddress);
                LOG("ContextFlags: %d\n", threadContext.threadContext64.ContextFlags);
                LOG("Rax: 0x%08llx Rbx: 0x%08llx Rcx: 0x%08llx Rdx: 0x%08llx Rsp: 0x%08llx Rbp: 0x%08llx Rsi: 0x%08llx"
                    "Rdi: 0x%08llx R8: 0x%08llx R9: 0x%08llx R10: 0x%08llx R11: 0x%08llx R12: 0x%08llx R13: 0x%08llx "
                    "R14: 0x%08llx "
                    "R15: 0x%08llx Rip: 0x%08llx\n", threadContext.threadContext64.Rax,
                    threadContext.threadContext64.Rbx, threadContext.threadContext64.Rcx,
                    threadContext.threadContext64.Rdx, threadContext.threadContext64.Rsp,
                    threadContext.threadContext64.Rbp, threadContext.threadContext64.Rsi,
                    threadContext.threadContext64.Rdi, threadContext.threadContext64.R8,
                    threadContext.threadContext64.R9, threadContext.threadContext64.R10,
                    threadContext.threadContext64.R11, threadContext.threadContext64.R12,
                    threadContext.threadContext64.R13, threadContext.threadContext64.R14,
                    threadContext.threadContext64.R15, threadContext.threadContext64.Rip);

                memcpy(&pInjEvent->RawDump,
                       &threadContext.threadContext64,
                       MIN((OFFSET_OF(CONTEXT64, Rip) + sizeof(QWORD)), sizeof(pInjEvent->RawDump)));

                pInjEvent->DumpValid = TRUE;

                pInjEvent->CopySize = MIN((OFFSET_OF(CONTEXT64, Rip) + sizeof(QWORD)), sizeof(pInjEvent->RawDump));

                IntDumpBuffer(pInjEvent->RawDump,
                              0,
                              (OFFSET_OF(CONTEXT64, Rip) - OFFSET_OF(CONTEXT64, Rax) + sizeof(QWORD)),
                              16,
                              sizeof(BYTE),
                              0,
                              0);
            }
        }
        else
        {
            if (!bIsDumpValid)
            {
                pInjEvent->DumpValid = FALSE;
            }
            else
            {
                LOG("Dumping CONTEXT registers %llx...", dstAddress);
                LOG("ContextFlags: %d\n", threadContext.threadContext32.ContextFlags);
                LOG("Eax: 0x%08x Ebx: 0x%08x Ecx: 0x%08x Edx: 0x%08x Esp: 0x%08x Ebp: 0x%08x Esi: 0x%08x Edi: 0x%08x "
                    "Eip: 0x%08x\n", threadContext.threadContext32.Eax, threadContext.threadContext32.Ebx,
                    threadContext.threadContext32.Ecx, threadContext.threadContext32.Edx,
                    threadContext.threadContext32.Esp, threadContext.threadContext32.Ebp,
                    threadContext.threadContext32.Esi, threadContext.threadContext32.Edi,
                    threadContext.threadContext32.Eip);

                memcpy(&pInjEvent->RawDump,
                       &threadContext.threadContext32,
                       MIN((OFFSET_OF(CONTEXT32, ExtendedRegisters) - OFFSET_OF(CONTEXT32, ContextFlags)),
                           sizeof(pInjEvent->RawDump)));

                pInjEvent->DumpValid = TRUE;

                pInjEvent->CopySize = MIN((OFFSET_OF(CONTEXT32, ExtendedRegisters) -
                                           OFFSET_OF(CONTEXT32, ContextFlags)), sizeof(pInjEvent->RawDump));

                IntDumpBuffer(pInjEvent->RawDump,
                              0,
                              (OFFSET_OF(CONTEXT32, ExtendedRegisters) - OFFSET_OF(CONTEXT32, ContextFlags)),
                              16,
                              sizeof(BYTE),
                              0,
                              0);
            }
        }

        pInjEvent->Header.Action = action;
        pInjEvent->Header.Reason = reason;
        pInjEvent->Header.MitreID = idProcInject;

        IntAlertFillCpuContext(FALSE, &pInjEvent->Header.CpuContext);
        IntAlertFillWinProcess(pProcOrig, &pInjEvent->Originator.Process);
        IntAlertFillWinProcess(pProcVictim, &pInjEvent->Victim.Process);
        IntAlertFillWinProcessByCr3(pInjEvent->Header.CpuContext.Cr3, &pInjEvent->Header.CurrentProcess);

        if (victim.Object.Library.Module)
        {
            IntAlertFillWinUmModule(victim.Object.Library.Module, &pInjEvent->Victim.Module);
        }

        if (victim.Object.Library.Export != NULL)
        {
            WIN_PROCESS_MODULE *pModule = victim.Object.Library.Module;
            WINUM_CACHE_EXPORT *pExport = victim.Object.Library.Export;

            for (DWORD export = 0; export < pExport->NumberOfOffsets; export++)
            {
                strlcpy(pInjEvent->Export.Name[export], pExport->Names[export],
                        MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[export] + 1));
                pInjEvent->Export.Hash[export] = Crc32Compute(pExport->Names[export],
                                                              pExport->NameLens[export], INITIAL_CRC_VALUE);
            }

            strlcpy(pInjEvent->FunctionName, pExport->Names[0],
                    MIN(ALERT_MAX_FUNCTION_NAME_LEN,  pExport->NameLens[0] + 1));
            pInjEvent->FunctionNameHash = Crc32Compute(pExport->Names[0],
                                                       pExport->NameLens[0], INITIAL_CRC_VALUE);

            if (pModule != NULL)
            {
                DWORD writeRva = (DWORD)(dstAddress - pModule->VirtualBase);
                pInjEvent->Export.Delta = writeRva - victim.Object.Library.Export->Rva;
            }
        }

        pInjEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_SET_THREAD_CTX, pProcVictim, reason, 0);

        // Set the internal information
        pInjEvent->DestinationVirtualAddress = kthreadVictim;
        pInjEvent->SourceVirtualAddress = kthreadOriginator;

        pInjEvent->ViolationType = memCopyViolationSetContextThread;

        IntAlertFillVersionInfo(&pInjEvent->Header);

        status = IntNotifyIntroEvent(introEventInjectionViolation, pInjEvent, sizeof(*pInjEvent));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = INT_STATUS_SUCCESS;
    }

cleanup_and_exit:
    if (NULL != pProcVictim)
    {
        IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_EXPLOIT, pProcVictim, &action);
    }

    status = IntDetSetReturnValue(Detour, regs,
                                  (action == introGuestNotAllowed) ? WIN_STATUS_ACCESS_DENIED : WIN_STATUS_SUCCESS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinThrHandleQueueApc(
    _In_ void *Detour
    )
///
/// @brief      Handles a NtQueueApcThreadEx call - blocking process injections.
/// @ingroup    group_detours
///
/// Asynchronous Procedure Call (APC) injection involves attaching malicious code to the APC Queue of a process's
/// thread. Queued APC functions are executed when the thread enters an alterable state. A variation of APC injection,
/// dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and
/// executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC.
/// AtomBombing is another variation that utilizes APCs to invoke malicious code previously written to the
/// global atom table.
/// https://attack.mitre.org/techniques/T1055/
///
/// @param[in]  Detour         The detour.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
///
{
    INTSTATUS status;
    INTRO_ACTION action;
    QWORD ethreadOriginator;
    QWORD eprocessOriginator;
    QWORD victimThread;
    QWORD eprocessVictim;
    INTRO_ACTION_REASON reason;
    EXCEPTION_UM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;
    QWORD rip;
    QWORD functionAddr, functionParameter;
    QWORD args[4];
    WIN_PROCESS_OBJECT *pOrigProc, *pVictimProc;
    WIN_PROCESS_MODULE *pMod;
    WINUM_CACHE_EXPORT *currentExport;

    action = introGuestAllowed;
    reason = introReasonAllowed;
    pVictimProc = pOrigProc = NULL;
    pMod = NULL;
    currentExport = NULL;
    rip = functionAddr = functionParameter = 0;

    status = IntDetGetArguments(Detour, 4, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    victimThread = args[0];
    functionAddr = args[1];
    functionParameter = args[2];
    ethreadOriginator = args[3];

    eprocessOriginator = ethreadOriginator + WIN_KM_FIELD(Thread, Process);

    status = IntKernVirtMemRead(eprocessOriginator, gGuest.WordSize, &eprocessOriginator, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pOrigProc = IntWinProcFindObjectByEprocess(eprocessOriginator);
    if (pOrigProc == NULL)
    {
        LOG("IntWinProcFindObjectByEprocess failed for originator! \n");
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    eprocessVictim = victimThread + WIN_KM_FIELD(Thread, Process);

    status = IntKernVirtMemRead(eprocessVictim, gGuest.WordSize, &eprocessVictim, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pVictimProc = IntWinProcFindObjectByEprocess(eprocessVictim);
    if (pVictimProc == NULL)
    {
        LOG("IntWinProcFindObjectByEprocess failed for victim! \n");
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    if (!pVictimProc->Protected || !pVictimProc->ProtQueueApc)
    {
        goto cleanup_and_exit;
    }

    if (eprocessVictim == eprocessOriginator)
    {
        goto cleanup_and_exit;
    }

    STATS_ENTER(statsExceptionsUser);

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    status = IntExceptUserGetOriginator(pOrigProc, FALSE, 0, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptUserGetOriginator failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        goto send_notification;
    }

    // wow64!NtQueueApcThread will pass to ntdll!NtQueueApcThread the "target function" parameter into EDX
    // (which in kernel mode will be moved into r8) as (-Target) << 2.
    // non-wow64 processes should call RtlQueueApcWow64Thread for a wow64 target. This will also do the
    // targetFunction << 2 * (-1) before actually doing the syscall.
    if (pOrigProc->Wow64Process || pVictimProc->Wow64Process)
    {
        rip = (functionAddr * (-1)) >> 2;
    }
    else
    {
        rip = functionAddr;
    }

    // Calling QueueUserAPC (documented function which will let you queue an APC on a function with 1 parameter)
    // will cause the following mechanism:
    // 1. Call ntdll!NtQueueApcThread with the following params: param1 (function address): RtlDispatchApc,
    //      param2 (first function param): real function address
    //      param3 the parameter passed to the real function from the QueueUserAPC call
    // 2. The kernel will then give control to RtlDispatchApc by delivering an APC
    // 3. RtlDispatchApc takes at least 2 parameters: the function to call and the parameter passed to the function
    //    to call
    // 4. RtlDispatchApc will call the function given by first parameter with the second parameter given as a parameter
    //    to the function
    // So, the real function will actually be the next parameter passed to NtQueueApcThreadEx
    pMod = IntWinUmModFindByAddress(pVictimProc, rip);
    if (pMod == NULL)
    {
        goto not_rtl_dispatch;
    }

    currentExport = IntWinUmModCacheExportFind(pMod, (DWORD)(rip - pMod->VirtualBase), 0);
    if (currentExport == NULL)
    {
        goto not_rtl_dispatch;
    }

    // Search for export RtlDispatchApc. Note that there might be multiple export names on one export
    // rva, therefore we must verify each name for the current cached export.
    for (DWORD i = 0; i < currentExport->NumberOfOffsets; i++)
    {
        if (0 == strncasecmp(currentExport->Names[i], "RtlDispatchApc", currentExport->NameLens[i]))
        {
            // This means that the function parameter is the actual RIP which the function RtlDispatchApc
            // will dispatch to (most probably a call from kernel32!QueueUserAPC).
            rip = functionParameter;
            break;
        }
    }

not_rtl_dispatch:
    // We put length 1 because of the following reason: on APC injections the length of the "injected" buffer should be
    // 0, but 0 won't match on delta exports checks (it will check RVA + length - 1 > delta), and it will not match as
    // it is a comparison of 2 DWORDS, so we put 1 as a "dummy" access size so that we avoid this problem.
    status = IntExceptGetVictimProcess(pVictimProc, rip, 1, ZONE_PROC_THREAD_APC | ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetModifiedProcess failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        goto send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_QUEUE_APC, pVictimProc, &action, &reason))
    {
        EVENT_MEMCOPY_VIOLATION *pInjEvent = &gAlert.Injection;

        memzero(pInjEvent, sizeof(*pInjEvent));

        LOG("[APC HIJACKING] From process '%s' into process '%s' (%llx [%llx] -> %llx [%llx]) to rip %llx\n",
            pOrigProc->Name, pVictimProc->Name, eprocessOriginator, ethreadOriginator,
            eprocessVictim, victimThread, rip);

        pInjEvent->Header.Action = action;
        pInjEvent->Header.Reason = reason;
        pInjEvent->Header.MitreID = idProcInject;

        status = IntVirtMemRead(rip, sizeof(pInjEvent->RawDump), pVictimProc->Cr3, pInjEvent->RawDump, NULL);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntVirtMemRead failed: 0x%08x\n", status);
            pInjEvent->DumpValid = FALSE;
        }
        else
        {
            pInjEvent->DumpValid = TRUE;
            pInjEvent->CopySize = sizeof(pInjEvent->RawDump);

            IntDumpBuffer(pInjEvent->RawDump, 0, sizeof(pInjEvent->RawDump), 16, sizeof(BYTE), 0, 0);
        }

        IntAlertFillCpuContext(FALSE, &pInjEvent->Header.CpuContext);
        IntAlertFillWinProcess(pOrigProc, &pInjEvent->Originator.Process);
        IntAlertFillWinProcess(pVictimProc, &pInjEvent->Victim.Process);
        IntAlertFillWinProcessByCr3(pInjEvent->Header.CpuContext.Cr3, &pInjEvent->Header.CurrentProcess);

        if (victim.Object.Library.Module)
        {
            IntAlertFillWinUmModule(victim.Object.Library.Module, &pInjEvent->Victim.Module);
        }

        if (victim.Object.Library.Export != NULL)
        {
            WIN_PROCESS_MODULE *pModule = victim.Object.Library.Module;
            WINUM_CACHE_EXPORT *pExport = victim.Object.Library.Export;

            for (DWORD export = 0; export < pExport->NumberOfOffsets; export++)
            {
                strlcpy(pInjEvent->Export.Name[export], pExport->Names[export],
                        MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[export] + 1));
                pInjEvent->Export.Hash[export] = Crc32Compute(pExport->Names[export],
                                                              pExport->NameLens[export], INITIAL_CRC_VALUE);
            }

            strlcpy(pInjEvent->FunctionName, pExport->Names[0],
                    MIN(ALERT_MAX_FUNCTION_NAME_LEN,  pExport->NameLens[0] + 1));
            pInjEvent->FunctionNameHash = Crc32Compute(pExport->Names[0],
                                                       pExport->NameLens[0], INITIAL_CRC_VALUE);

            if (pModule != NULL)
            {
                DWORD writeRva = (DWORD)(rip - pModule->VirtualBase);
                pInjEvent->Export.Delta = writeRva - victim.Object.Library.Export->Rva;
            }
        }

        pInjEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_QUEUE_APC, pVictimProc, reason, 0);

        // Set the internal information
        pInjEvent->DestinationVirtualAddress = rip;
        pInjEvent->SourceVirtualAddress = victimThread;

        pInjEvent->ViolationType = memCopyViolationQueueApcThread;

        IntAlertFillVersionInfo(&pInjEvent->Header);

        status = IntNotifyIntroEvent(introEventInjectionViolation, pInjEvent, sizeof(*pInjEvent));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

cleanup_and_exit:

    if (NULL != pVictimProc)
    {
        IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_QUEUE_APC, pVictimProc, &action);
    }

    status = IntDetSetReturnValue(Detour, &gVcpu->Regs,
                                  (action == introGuestNotAllowed) ? WIN_STATUS_ACCESS_DENIED : WIN_STATUS_SUCCESS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: 0x%08x\n", status);
    }

    return status;

}


INTSTATUS
IntWinThrPatchThreadHijackHandler(
    _In_ QWORD FunctionAddress,
    _Inout_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "PspSetContextThreadInternal".
/// @ingroup    group_detours
///
/// This function is called before the hook is placed into memory in order to "patch" the addresses of guest functions
/// or guest file offsets that are used by the hook handler. Specifically, this patches the offsets of the AttachedProcess
/// and Process fields of _KTHREAD and the Spare field of _KPROCESS, but also patches the "retn" instruction accordingly.
///
/// @param[in]  FunctionAddress       The address of the function.
/// @param[in]  Handler               An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor            Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS   Always.
///
{

    PAPI_HOOK_HANDLER pHandler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    pHandler = (PAPI_HOOK_HANDLER)Handler;

    if (!gGuest.Guest64)
    {

        *(DWORD *)(pHandler->Code + 0x8) = WIN_KM_FIELD(Thread, AttachedProcess);

        *(DWORD *)(pHandler->Code + 0x12) = WIN_KM_FIELD(Thread, Process);

        *(DWORD *)(pHandler->Code + 0x18) = WIN_KM_FIELD(Process, Spare);

        if (gGuest.OSVersion <= 9200 || gGuest.OSVersion == 10240 ||
            (gGuest.OSVersion >= 14393 && gGuest.OSVersion <= 18362))
        {
            // Patch the ret (it is retn 0x14 on these OSes)
            pHandler->Code[0x41] = 0x14;
        }
        else
        {
            // At offset 2 we have `mov    ecx,DWORD PTR [esp+0xc]` instruction, but on 8.1 and
            // 10586 and seemingly on 20H1 the injected thread is in ECX
            // so we will patch the instruction with 4 nops
            *(DWORD *)(pHandler->Code + 0x2) = 0x90909090;

            // We have `cmp    eax,DWORD PTR [esp+0xc]`, here we patch the 0xc, as the thread is at
            // [esp+0x0] because we have pushed ECX on the stack
            pHandler->Code[0x2f] = 0x00;

            // Finally patch the ret (it is retn 0x0C on these OSes)
            pHandler->Code[0x41] = 0x0C;
        }
    }
    else
    {
        *(DWORD *)(pHandler->Code + 0x4) = WIN_KM_FIELD(Thread, AttachedProcess);

        *(DWORD *)(pHandler->Code + 0x10) = WIN_KM_FIELD(Thread, Process);

        *(DWORD *)(pHandler->Code + 0x17) = WIN_KM_FIELD(Process, Spare);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinThrPrepareApcHandler(
    _In_ QWORD FunctionAddress,
    _Inout_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "NtQueueApcThreadEx".
/// @ingroup    group_detours
///
/// This function is called before the hook is placed into memory in order to "patch" the addresses of guest functions
/// or guest file offsets that are used by the hook handler. Specifically, this patches the addresses of PsThreadType,
/// ObReferenceObjectByHandle, ObDereferenceObject and the offsets of the AttachedProcess and Process fields of _KTHREAD
/// and the Spare field of _KPROCESS, but also patches the "retn" instruction accordingly.
///
/// @param[in]  FunctionAddress         The address of the function.
/// @param[in]  Handler                 An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor              Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    PAPI_HOOK_HANDLER pHandler;
    QWORD *threadType, *referenceObj, *derefObj;
    DWORD *attachedProc, *process, *spare;
    DWORD *threadType32, *referenceObj32, *derefObj32;
    PCHAR exports[3] = { "PsThreadType", "ObReferenceObjectByHandle", "ObDereferenceObject" };
    QWORD gvas[3] = { 0, 0, 0 };
    DWORD offsetCallObReferenceObject, offsetCallObDereference,
          offsetPsThreadType, offsetAttachedProcess, offsetProcess, offsetSpare;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    threadType = referenceObj = derefObj = NULL;
    threadType32 = referenceObj32 = derefObj32 = NULL;
    attachedProc = process = spare = NULL;

    pHandler = (PAPI_HOOK_HANDLER)Handler;

    if (gGuest.Guest64)
    {
        offsetCallObReferenceObject = 0x3b;
        offsetCallObDereference = 0xa0;
        offsetPsThreadType = 0x11;
        offsetAttachedProcess = 0x5f;
        offsetProcess = 0x6b;
        offsetSpare = 0x72;

        threadType = (QWORD *)&pHandler->Code[offsetPsThreadType];
        referenceObj = (QWORD *)&pHandler->Code[offsetCallObReferenceObject];
        derefObj = (QWORD *)&pHandler->Code[offsetCallObDereference];
        attachedProc = (DWORD *)&pHandler->Code[offsetAttachedProcess];
        process = (DWORD *)&pHandler->Code[offsetProcess];
        spare = (DWORD *)&pHandler->Code[offsetSpare];
    }
    else
    {
        offsetPsThreadType = 0x1d;
        offsetCallObReferenceObject = 0x25;
        offsetCallObDereference = 0x67;
        offsetAttachedProcess = 0x35;
        offsetProcess = 0x3f;
        offsetSpare = 0x45;

        threadType32 = (DWORD *)&pHandler->Code[offsetPsThreadType];
        referenceObj32 = (DWORD *)&pHandler->Code[offsetCallObReferenceObject];
        derefObj32 = (DWORD *)&pHandler->Code[offsetCallObDereference];
        attachedProc = (DWORD *)&pHandler->Code[offsetAttachedProcess];
        process = (DWORD *)&pHandler->Code[offsetProcess];
        spare = (DWORD *)&pHandler->Code[offsetSpare];
    }

    for (DWORD i = 0; i < 3; i++)
    {
        status = IntPeFindKernelExport(exports[i], &gvas[i]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Cannot find export %s for patching APC thread handler!\n", exports[i]);
            return status;
        }
        else
        {
            TRACE("[INFO] Export %s found at gva %016llx\n", exports[i], gvas[i]);
        }
    }

    if (gGuest.Guest64)
    {
        threadType[0] = gvas[0];
        referenceObj[0] = gvas[1];
        derefObj[0] = gvas[2];
        attachedProc[0] = WIN_KM_FIELD(Thread, AttachedProcess);
        process[0] = WIN_KM_FIELD(Thread, Process);
        spare[0] = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        threadType32[0] = (DWORD)gvas[0];
        referenceObj32[0] = (DWORD)gvas[1];
        derefObj32[0] = (DWORD)gvas[2];
        attachedProc[0] = WIN_KM_FIELD(Thread, AttachedProcess);
        process[0] = WIN_KM_FIELD(Thread, Process);
        spare[0] = WIN_KM_FIELD(Process, Spare);
    }

    TRACE("[INFO] Successfully patched NtQueueApcThreadEx handler!\n");

    return INT_STATUS_SUCCESS;
}
