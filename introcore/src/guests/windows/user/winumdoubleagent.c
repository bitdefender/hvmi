/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winummodule.h"
#include "winummoduleblock.h"
#include "alerts.h"
#include "guests.h"
#include "swapmem.h"


///
/// The list of DLLs that can be loaded before kernel32.dll is loaded.
///
const PROTECTED_DLL_INFO gInitialDlls[] =
{
    { u"ntdll.dll",             NAMEHASH_NTDLL },
    { u"kernel32.dll",          NAMEHASH_KERNEL32 },
    { u"verifier.dll",          NAMEHASH_VERIFIER },
    { u"apisetschema.dll",      NAMEHASH_APISETSCHEMA },
};


static INTSTATUS
IntWinDagentSendDoubleAgentAlert(
    _In_ const WIN_PROCESS_MODULE *Module,
    _In_opt_ const WIN_PROCESS_MODULE *ReturnModule,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ QWORD RetAddr
    )
///
/// @brief Sends a DoubleAgent alert.
///
/// When a DoubleAgent like attack is identified, this function will construct and send a
/// #introEventModuleLoadViolation alert to the integrator.
///
/// @param[in]  Module          The module that got maliciously loaded.
/// @param[in]  ReturnModule    The return module.
/// @param[in]  Action          The taken action.
/// @param[in]  Reason          The action reason.
/// @param[in]  RetAddr         The address the module will return at.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    EVENT_MODULE_LOAD_VIOLATION *pModLoad = &gAlert.ModuleLoad;
    IMAGE_SECTION_HEADER sectionHeader;
    INTSTATUS status = INT_STATUS_SUCCESS;

    memzero(pModLoad, sizeof(*pModLoad));

    pModLoad->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_DOUBLE_AGENT, Module->Subsystem->Process, Reason, 0);
    if (IntPolicyProcIsBeta(Module->Subsystem->Process, PROC_OPT_PROT_DOUBLE_AGENT))
    {
        pModLoad->Header.Flags |= ALERT_FLAG_BETA;
    }

    pModLoad->Header.Action = Action;
    pModLoad->Header.Reason = Reason;
    pModLoad->Header.MitreID = idExecModLoad;

    IntAlertFillCpuContext(FALSE, &pModLoad->Header.CpuContext);
    IntAlertFillWinProcessCurrent(&pModLoad->Header.CurrentProcess);
    IntAlertFillWinUmModule(Module, &pModLoad->Originator.Module);
    IntAlertFillWinProcess(Module->Subsystem->Process, &pModLoad->Victim);
    IntAlertFillWinUmModule(ReturnModule, &pModLoad->Originator.ReturnModule);

    pModLoad->ReturnRip = RetAddr;

    if (NULL != ReturnModule)
    {
        status = IntPeGetSectionHeaderByRva(ReturnModule->VirtualBase,
                                            NULL,
                                            (DWORD)(RetAddr - ReturnModule->VirtualBase),
                                            &sectionHeader);
        if (INT_SUCCESS(status))
        {
            memcpy(pModLoad->ReturnRipSectionName, sectionHeader.Name, sizeof(sectionHeader.Name));
        }
    }

    status = IntPeGetSectionHeaderByRva(Module->VirtualBase,
                                        NULL,
                                        (DWORD)(gVcpu->Regs.Rip - Module->VirtualBase),
                                        &sectionHeader);
    if (INT_SUCCESS(status))
    {
        memcpy(pModLoad->RipSectionName, sectionHeader.Name, sizeof(sectionHeader.Name));
    }

    IntAlertFillVersionInfo(&pModLoad->Header);

    status = IntNotifyIntroEvent(introEventModuleLoadViolation, pModLoad, sizeof(*pModLoad));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinDagentHandleDoubleAgent(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_opt_ const WIN_PROCESS_MODULE *ReturnModule,
    _Out_ INTRO_ACTION *Action,
    _In_ QWORD RetAddr
    )
///
/// @brief Handles a DoubleAgent module load.
///
/// This module handles a DoubleAgent-like module being loaded inside a process. If it determines the attempt
/// is malicious, it will block it and it will send an alert.
///
/// @param[in]  Module          The module that was loaded.
/// @param[in]  ReturnModule    Return module.
/// @param[out] Action          The desired action.
/// @param[in]  RetAddr         The return address.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTSTATUS status;

    INTRO_ACTION action = introGuestNotAllowed;
    INTRO_ACTION_REASON reason = introReasonInternalError;

    STATS_ENTER(statsExceptionsUser);

    status = IntExceptUserGetOriginator(Module->Subsystem->Process,
                                        TRUE,
                                        Module->VirtualBase,
                                        NULL,
                                        &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _send_notification;
    }

    status = IntExceptGetVictimProcess(Module->Subsystem->Process,
                                       Module->VirtualBase,
                                       1,
                                       ZONE_WRITE | ZONE_MODULE_LOAD,
                                       &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventModuleLoadViolation);

_send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_DOUBLE_AGENT, Module->Subsystem->Process, &action, &reason))
    {
        if (Module->DoubleAgentAlertSent)
        {
            goto _skip_send_nodification;
        }

        IntWinProcSendAllDllEventsForProcess(Module->Subsystem->Process);

        LOG("[MODULE] Suspicious DLL '%s' loaded BEFORE kernel32 at %llx:%x!\n",
            utf16_for_log(Module->Path->Path), Module->VirtualBase, Module->Size);

        status = IntWinDagentSendDoubleAgentAlert(Module, ReturnModule, action, reason, RetAddr);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinDagentSendDoubleAgentAlert failed: 0x%08x\n", status);
        }

        Module->DoubleAgentAlertSent = TRUE;
    }

_skip_send_nodification:
    *Action = action;

    IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_DOUBLE_AGENT, Module->Subsystem->Process, Action);

    return status;
}


static INTSTATUS
IntWinDagentHandleSlackWritable(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) const BYTE *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief Swapmem callback which is called when the desired area between suspicious
/// module section was swapped-in and made writable.
///
/// We need some space inside the given module so that we initialize the
/// RTL_VERIFIER_PROVIDER_DESCRIPTOR structure needed for verifier.dll. Without
/// this structure initialized, the verifier engine will close the process with
/// STATUS_DLL_INIT_FAILED, which is not desired. Thus, we get some space from within
/// the module, which is writable, and we give it to the verifier engine, which
/// thinks it is given by the possible malicious DLL.
///
/// @param[in]  Context             The #WIN_PROCESS_MODULE structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;
    WIN_PROCESS_MODULE *pMod = Context;
    DWORD addrSize;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    STATS_ENTER(statsModuleLoadViolation);

    pMod->SlackSpaceSwapHandle = NULL;

    if (pMod->Subsystem->SubsystemType == winSubsys64Bit)
    {
        RTL_VERIFIER_PROVIDER_DESCRIPTOR_64 tVpd;
        RTL_VERIFIER_DLL_DESCRIPTOR_64 atDlls = { 0 };
        addrSize = 8;

        memzero(&tVpd, sizeof(tVpd));

        status = IntVirtMemWrite(pMod->SlackSpaceForVerifier,
                                 sizeof(RTL_VERIFIER_DLL_DESCRIPTOR_64),
                                 pMod->Subsystem->Process->Cr3,
                                 &atDlls);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto _exit;
        }

        tVpd.dwLength = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR_64);
        tVpd.pvProviderDlls = pMod->SlackSpaceForVerifier;

        pMod->SlackSpaceForVerifier += sizeof(atDlls);

        status = IntVirtMemWrite(pMod->SlackSpaceForVerifier,
                                 sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR_64),
                                 pMod->Subsystem->Process->Cr3,
                                 &tVpd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto _exit;
        }

        status = IntVirtMemWrite(pMod->AddressOfVerifierData,
                                 addrSize,
                                 pMod->Subsystem->Process->Cr3,
                                 &pMod->SlackSpaceForVerifier);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto _exit;
        }
    }
    else
    {
        RTL_VERIFIER_PROVIDER_DESCRIPTOR_32 tVpd;
        RTL_VERIFIER_DLL_DESCRIPTOR_32 atDlls = { 0 };
        addrSize = 4;

        memzero(&tVpd, sizeof(tVpd));

        status = IntVirtMemWrite(pMod->SlackSpaceForVerifier,
                                 sizeof(RTL_VERIFIER_DLL_DESCRIPTOR_32),
                                 pMod->Subsystem->Process->Cr3,
                                 &atDlls);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto _exit;
        }

        tVpd.dwLength = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR_32);
        tVpd.pvProviderDlls = (DWORD)pMod->SlackSpaceForVerifier;

        pMod->SlackSpaceForVerifier += sizeof(atDlls);

        status = IntVirtMemWrite(pMod->SlackSpaceForVerifier,
                                 sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR_32),
                                 pMod->Subsystem->Process->Cr3,
                                 &tVpd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto _exit;
        }

        status = IntVirtMemWrite(pMod->AddressOfVerifierData,
                                 addrSize,
                                 pMod->Subsystem->Process->Cr3,
                                 &pMod->SlackSpaceForVerifier);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
        }
    }

_exit:
    STATS_EXIT(statsModuleLoadViolation);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDagentHandleSuspModExecution(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ void *BlockObject,
    _In_ QWORD DllHandle,
    _In_ QWORD Reason,
    _In_ QWORD Reserved,
    _In_ QWORD RetAddress,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief Callback for module block mechanism, being called whenever executions take place in the possible
/// malicious DLL.
///
/// This is the main callback which contains the logic whenever an execution takes place in a possible malicious
/// DLL, verifying some heuristics so that the Introcore engine can be sure that we are on a double agent case,
/// such as verifying that the process main module is from native subsystem, in which case it means that the module
/// is not loading kernel32.dll, thus the initial heuristic regarding loading before kernel32.dll would not stand.
/// Other verification like the return module and whether we have a slack space to write the needed verifier
/// structure are made, as well as checking against the exception mechanism through #IntWinDagentHandleDoubleAgent.
/// Note: DllHandle, Reason, Reserved will be equal to #WINMODBLOCK_INVALID_VALUE if the execution took place
/// on something different than DllMain.
///
/// @param[in]  Module          The module which made an execution and is considered suspicious.
/// @param[in]  BlockObject     The #WIN_MOD_BLOCK_OBJECT used for operations involving the module block mechanism.
/// @param[in]  DllHandle       The first parameter of DllMain.
/// @param[in]  Reason          The second parameter of DllMain.
/// @param[in]  Reserved        The third parameter of DllMain.
/// @param[in]  RetAddress      The RIP address which called the suspicious module.
/// @param[in, out] Action      The #INTRO_ACTION returned to module block mechanism.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED If the slack space between sections was not found during the
/// headers parsing phase.
///
{
    WIN_PROCESS_MODULE *pMod = Module;
    WIN_PROCESS_MODULE *pReturnModule = NULL;
    INTSTATUS status = INT_STATUS_SUCCESS;
    INTSTATUS status2;

    UNREFERENCED_PARAMETER(BlockObject);

    // Skip processes with image from native subsystem
    if (pMod->Subsystem->Process->ImageIsFromNativeSubsystem)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    *Action = introGuestNotAllowed;

    pReturnModule = IntWinUmModFindByAddress(pMod->Subsystem->Process, RetAddress);
    if (NULL == pReturnModule)
    {
        ERROR("[ERROR] Could not find a return module\n");
    }

    if (!pMod->Subsystem->Process->IsVerifierLoaded)
    {
        pMod->SlackSpaceForVerifier = 0;
        pMod->AddressOfVerifierData = 0;

        *Action = introGuestAllowed;

        return INT_STATUS_SUCCESS;
    }

    // If all these are invalid, it means that something else than the entry point was called - just send alert
    if (DllHandle == WINMODBLOCK_INVALID_VALUE &&
        Reason == WINMODBLOCK_INVALID_VALUE &&
        Reserved == WINMODBLOCK_INVALID_VALUE)
    {
        goto _check_exc_and_send_alert;
    }

    LOG("[INFO] DllMain for %s called with Reason %lld\n", utf16_for_log(pMod->Path->Path), Reason);

    // Get the address of the structure which needs to be completed on verifier load
    // (RTL_VERIFIER_PROVIDER_DESCRIPTOR, see Alex Ionescu's presentation "Esoteric Hooks"
    // http://www.alex-ionescu.com/Estoteric%20Hooks.pdf for more details)
    if (pMod->AddressOfVerifierData == 0 && Reason == DLL_VERIFIER_PROVIDER)
    {
        pMod->AddressOfVerifierData = Reserved;
    }

    if (!Module->SlackSpaceForVerifier)
    {
        status = INT_STATUS_NOT_INITIALIZED;
        goto _check_exc_and_send_alert;
    }

    if (NULL != pReturnModule &&
        (pReturnModule->Path->NameHash != NAMEHASH_VERIFIER ||
         0 != wstrcasecmp(pReturnModule->Path->Name, u"verifier.dll")) &&
        !pMod->FirstDoubleAgentExecDone)
    {
        TRACE("[INFO] Return module name for this exec: `%s` (%016llx) for process: `%s` PID: %d dll: `%s`\n",
              utf16_for_log(pReturnModule->Path->Name),
              RetAddress,
              pMod->Subsystem->Process->Name,
              pMod->Subsystem->Process->Pid,
              utf16_for_log(pMod->Path->Path));
    }

_check_exc_and_send_alert:
    if (!pMod->FirstDoubleAgentExecDone && Reason != DLL_VERIFIER_PROVIDER && !pMod->IsSuspicious)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    status2 = IntWinDagentHandleDoubleAgent(Module, pReturnModule, Action, RetAddress);
    if (!INT_SUCCESS(status2))
    {
        ERROR("[ERROR] IntWinDagentHandleDoubleAgent failed: 0x%08x\n", status2);
    }

    return status;
}


static INTSTATUS
IntWinDagentHandleSuspModHeaders(
    _Inout_ WIN_PROCESS_MODULE *Module,
    _In_ BYTE *Headers
    )
///
/// @brief Callback called through module block mechanism when the suspicious module headers are in memory.
///
/// This callback will search, based on the given header, some place inside the suspicious module, between
/// sections, which can be writable and where we can put the RTL_VERIFIER_PROVIDER_DESCRIPTOR structure
/// which is needed for proper verifier engine initialization.
///
/// @param[in, out] Module  The #WIN_PROCESS_MODULE structure for the module which is considered suspicious.
/// @param[in]  Headers The MZPE headers of the given module.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    const DWORD minRequiredSize = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR_64) + sizeof(RTL_VERIFIER_DLL_DESCRIPTOR_64);
    const IMAGE_SECTION_HEADER *pSec = NULL;
    const IMAGE_SECTION_HEADER *pNextSec = NULL;
    DWORD sectionRva = 0;
    DWORD sectionCount = 0;
    BOOLEAN found = FALSE;

    STATS_ENTER(statsModuleLoadViolation);

    status = IntPeListSectionsHeaders(Module->VirtualBase, Headers, PAGE_SIZE, &sectionRva, &sectionCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeIterateSections failed with status: 0x%08x\n", status);
        return status;
    }

    pSec = (const IMAGE_SECTION_HEADER *)(Headers + sectionRva);
    for (DWORD iSec = 0; iSec < sectionCount; iSec++, pSec++)
    {
        if ((QWORD)pSec->VirtualAddress + pSec->Misc.VirtualSize > Module->Vad->PageCount * PAGE_SIZE)
        {
            continue;
        }

        if (!!(pSec->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            DWORD minSize = 0xFFFFFFFF;
            BOOLEAN foundSec = FALSE;

            // We search for a section which has the most near RVA to our current RVA + size
            // (considering it next section)
            pNextSec = (const IMAGE_SECTION_HEADER *)(Headers + sectionRva);
            for (DWORD iNextSec = 0; iNextSec < sectionCount; iNextSec++, pNextSec++)
            {
                if ((QWORD)pNextSec->VirtualAddress + pNextSec->Misc.VirtualSize > Module->Vad->PageCount * PAGE_SIZE)
                {
                    continue;
                }

                if ((pNextSec->VirtualAddress >= pSec->VirtualAddress + pSec->Misc.VirtualSize) &&
                    (pNextSec->VirtualAddress - pSec->VirtualAddress - pSec->Misc.VirtualSize) < minSize)
                {
                    minSize = (pNextSec->VirtualAddress - pSec->VirtualAddress - pSec->Misc.VirtualSize);
                    foundSec = TRUE;
                }
            }

            // If we didn't find any section, we consider the space between end_section and end_module
            if (!foundSec)
            {
                minSize = Module->Size - pSec->VirtualAddress - pSec->Misc.VirtualSize;
            }

            if (minSize >= minRequiredSize)
            {
                found = TRUE;
                break;
            }
        }
    }

    if (found)
    {
        Module->SlackSpaceForVerifier = Module->VirtualBase + pSec->VirtualAddress + pSec->Misc.VirtualSize;
        TRACE("[INFO] Found a good address 0x%016llx\n", Module->SlackSpaceForVerifier);
    }

    if (!found && Module->IsSuspicious)
    {
        WARNING("[WARNING] Did not found a valid slack space for verifier address, "
                "will kill process on first execution!\n");
    }

    STATS_EXIT(statsModuleLoadViolation);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDagentHandleVerifierReason(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ void *BlockObject,
    _In_ QWORD DllHandle,
    _In_ QWORD Reason,
    _In_ QWORD Reserved,
    _In_ QWORD RetAddress,
    _In_ INTRO_ACTION *Action
    )
///
/// @brief Called by the module block mechanism when DllMain was called with a specific Reason,
/// DLL_VERIFIER_PROVIDER in this case
///
/// We want to block all executions and send an alert whenever a suspicious module is called,
/// but in order to not cause a crash to the protected process, e.g. due to improper verifier engine
/// initialization, we need to do some preparatory steps in some cases. When the DLL_VERIFIER_PROVIDER
/// is given as a Reason to DllMain, the module is expected to complete a RTL_VERIFIER_PROVIDER_DESCRIPTOR
/// structure, so that the verifier engine can initialize properly. As we cannot rely on the suspicious
/// module execution, which may do malicious actions after the initialization of the structure, we should
/// initialize it. For this purpose, we have gathered when we have swapped in the headers an address
/// between the module's sections, where we'll put the structure, and at this point we will make it
/// writable (and obviously present in memory), so that the #IntWinDagentHandleSlackWritable callback
/// can complete the structure with the data needed by the verifier engine.
/// Note that this callback may issue an introGuestRetry action, which will keep re-executing the
/// DllMain first instruction, causing an EPT violation each time, until the page fault for the structure
/// was injected.
///
/// @param[in]  Module          The module which made an execution and is considered suspicious.
/// @param[in]  BlockObject     The #WIN_MOD_BLOCK_OBJECT used for operations involving the module block mechanism.
/// @param[in]  DllHandle       The first parameter of DllMain.
/// @param[in]  Reason          The second parameter of DllMain.
/// @param[in]  Reserved        The third parameter of DllMain.
/// @param[in]  RetAddress      The RIP address which called the suspicious module.
/// @param[in, out] Action      The #INTRO_ACTION returned to module block mechanism.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(BlockObject);
    UNREFERENCED_PARAMETER(DllHandle);
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(RetAddress);

    if (Module->Subsystem->Process->ImageIsFromNativeSubsystem)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    if (!Module->SlackSpaceForVerifier)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    // This is dll attach reason for verifier providers, where we have to trick verifier.dll that the suspicious dll
    // loaded for that we write 2 structures in a well chosen place and then just return TRUE
    if (DLL_VERIFIER_PROVIDER == Reason)
    {
        if (Module->FirstDoubleAgentExecDone)
        {
            // We have to retry execution as it is very possible that our swap-mem request didn't get handled on the
            // last exit so retry until it is swapped in.
            if (NULL != Module->SlackSpaceSwapHandle)
            {
                TRACE("[INFO] [DAGENT] Slack space not swapped-in yet, will retry.\n");
                *Action = introGuestRetry;
            }

            return status;
        }

        Module->FirstDoubleAgentExecDone = TRUE;

        // Also put the flag SWAPMEM_OPT_RW_FAULT as we want to handle CoW on the slack space page
        // Even if we have chosen a writable section, it can be copy on write - so before actually writing
        // in that page, we force the copy on write by injecting a write page fault.
        status = IntSwapMemReadData(Module->Subsystem->Process->Cr3,
                                    Module->SlackSpaceForVerifier,
                                    1,
                                    SWAPMEM_OPT_UM_FAULT | SWAPMEM_OPT_RW_FAULT,
                                    Module,
                                    0,
                                    IntWinDagentHandleSlackWritable,
                                    NULL,
                                    &Module->SlackSpaceSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            return status;
        }

        *Action = introGuestRetry;
    }
    else
    {
        ERROR("[ERROR] IntWinDagentHandleVerifierReason called for reason %llu\n", Reason);
    }

    return status;
}


static INTSTATUS
IntWinDagentCheckNativeSubsystem(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) BYTE *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief Swapmem callback for the main module headers of the possible affected process.
///
/// The processes which are from the Native Subsystem (IMAGE_SUBSYSTEM_NATIVE) will not load kernel32.dll
/// in the initialization phase, but rather will load if needed afterwards, most of the times, for system
/// processes, not loading it at all. This may cause some false positives and/or performance impact due
/// to checking all the modules, which are considered "before kernel32.dll" since it didn't load at all.
/// For this purpose, we will check that the process is from native subsystem, and will not check anymore
/// modules if it is.
///
/// @param[in]  Context             The #WIN_PROCESS_MODULE structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    WIN_PROCESS_MODULE *pMod = Context;
    INTRO_PE_INFO peInfo = { 0 };
    INTSTATUS status = INT_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    STATS_ENTER(statsModuleLoadViolation);

    pMod->MainModHeadersSwapHandle = NULL;

    status = IntPeValidateHeader(VirtualAddress, Data, DataSize, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        goto _exit;
    }

    if (IMAGE_SUBSYSTEM_NATIVE == peInfo.Subsystem)
    {
        TRACE("[INFO] `%s` is from native subsystem, will skip double agent hooks\n", utf16_for_log(pMod->Path->Path));
        pMod->Subsystem->Process->ImageIsFromNativeSubsystem = TRUE;
    }
    else
    {
        TRACE("[INFO] `%s` is NOT from native subsystem. Subsystem flag = %d\n", utf16_for_log(pMod->Path->Path),
              peInfo.Subsystem);
        pMod->Subsystem->Process->ImageIsFromNativeSubsystem = FALSE;
    }

_exit:
    STATS_EXIT(statsModuleLoadViolation);

    return status;
}


static INTSTATUS
IntWinModDagentSuspModCleanup(
    _Inout_ WIN_PROCESS_MODULE *Module,
    _In_ const void *BlockObject
    )
///
/// @brief Callback which is called from module block mechanism before the object is destroyed.
///
/// Before the object is destroyed, the module block will call this function so that one can make sure
/// that there are no more references to that module block object. The destruction of the object can
/// take place either because at some point the decision that the module is not suspicious was made
/// or because the DLL unloaded.
///
/// @param[in, out] Module  The #WIN_PROCESS_MODULE structure for which the module block object is destroyed.
/// @param[in]  BlockObject The module block object which is being destroyed.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE  When the given module is not associated with the given block object.
///
{
    if (BlockObject != Module->ModBlockObject)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    Module->ModBlockObject = NULL;

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntWinDagentIsInitialDll(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Check if a module is one of the modules listed in #gInitialDlls.
///
/// @param[in]  Module  The module to check.
///
/// @returns True if the indicated module belongs to #gInitialDlls, false otherwise.
///
{
    DWORD i;

    for (i = 0; i < ARRAYSIZE(gInitialDlls); i++)
    {
        if (Module->IsSystemModule && MODULE_MATCH(Module, &gInitialDlls[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntWinDagentCheckSuspiciousDllLoad(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Checks if the given module is suspicious of loading through the double agent technique and
/// calls the module block mechanism if it is.
///
/// This is the main function which is called on modules for checking if the double agent technique was
/// used or not. This function will check if verifier.dll is loaded in the current process and if
/// the current module is loaded before kernel32.dll. Take note that there are some cases like
/// the current module is excepted, and loads kernel32.dll, but some module, which is malicious, is also
/// loaded afterwards. For this purpose, we'll check all modules if verifier is loaded, and don't
/// consider a module malicious if it hasn't been called with DLL_VERIFIER_PROVIDER reason. This is also
/// the function where we start checking the native subsystem and we register the module block callbacks
/// for the suspicious modules, which will be called afterwards through the module block mechanism.
/// Note that we can only detect the technique and block it if we are at module load time. For statically
/// detected modules, there is very little to no evidence for such a DLL that it was loaded through double
/// agent, thus the detection cannot take place, and the execution blocking would not be of any use,
/// since the possible malicious part of the DLL was already executed.
///
/// @param[in]  Module  The module which is to be verified whether it is suspicious or not.
///
/// @retval     #INT_STATUS_SUCCESS On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT If the process is not protected, module was static detected or
/// other invalid configurations.
///
{
    INTSTATUS status;

    if (!Module->Subsystem->Process->ProtDoubleAgent)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Check if process image is from native subsystem
    if (Module->IsMainModule)
    {
        status = IntSwapMemReadData(Module->Subsystem->Process->Cr3,
                                    Module->VirtualBase,
                                    PAGE_SIZE,
                                    SWAPMEM_OPT_UM_FAULT,
                                    Module,
                                    0,
                                    IntWinDagentCheckNativeSubsystem,
                                    IntWinModHandlePreInjection,
                                    &Module->MainModHeadersSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            goto _clean_leave;
        }
    }

    if (Module->StaticScan)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // we won't put our hooks if process image is from native subsystem
    if (Module->Subsystem->Process->ImageIsFromNativeSubsystem)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // We can skip 64 bit subsystem on wow processes.
    if ((Module->Subsystem->SubsystemType == winSubsys64Bit) && Module->Subsystem->Process->Wow64Process)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if ((0 == Module->VirtualBase) || (0 == Module->Size))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (Module->SuspChecked)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (Module->IsSystemModule && Module->Path->NameHash == NAMEHASH_VERIFIER)
    {
        Module->Subsystem->Process->IsVerifierLoaded = TRUE;
    }

    // There is the case where gemmauf/other dependent kernel32 DLL
    // are loaded before and we except them. They will load kernel32 just before the suspicious module is loaded.
    // We will monitor all modules until DllMain is called and if the Reason is != 4 on the first call,
    // we'll not consider them malicious.
    // Also, we may have kernel32.dll with an incomplete path (so we can't verify it is a system
    // module or not) thus the check for kernel32 load count becomes a bit problematic, as every DLL is marked as
    // suspicious and is verified afterwards.
    // We shall do the checks only if verifier is already loaded in the process, marking it as suspicious
    // if there is no kernel32.dll loaded.
    if (Module->Subsystem->Process->IsVerifierLoaded && !Module->IsMainModule && !IntWinDagentIsInitialDll(Module))
    {
        // We will monitor other modules if verifier is loaded
        // but we'll consider them suspicious and "have a closer look" only if they are loaded before kernel32.dll
        Module->IsSuspicious = !Module->Subsystem->Kernel32LoadCount;

        status = IntWinModBlockBlockModuleLoad(Module,
                                               winModBlockFlagDoNotUnload | winModBlockFlagKillOnError,
                                               IntWinDagentHandleSuspModExecution,
                                               IntWinDagentHandleSuspModHeaders,
                                               IntWinModDagentSuspModCleanup,
                                               &Module->ModBlockObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModBlockBlockModuleLoad failed: 0x%08x\n", status);
            goto _clean_leave;
        }

        status = IntWinModBlockRegisterCallbackForReason(Module->ModBlockObject,
                                                         DLL_VERIFIER_PROVIDER,
                                                         IntWinDagentHandleVerifierReason);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModBlockRegisterCallbackForReason failed: 0x%08x\n", status);

            status = IntWinModBlockRemoveBlockObject(Module->ModBlockObject);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModBlockRemoveBlockObject failed: 0x%08x\n", status);
            }
        }
    }

_clean_leave:
    Module->SuspChecked = TRUE;

    return INT_STATUS_SUCCESS;
}
