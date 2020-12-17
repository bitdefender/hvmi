/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winummodule.h"
#include "alerts.h"
#include "hook.h"
#include "swapmem.h"
#include "unpacker.h"
#include "winprocesshp.h"
#include "winummoduleblock.h"
#include "winumdoubleagent.h"
#include "winthread.h"


///
/// Base name of every protected DLL. Note that only modules that won't be unloaded can be protected
/// for now, as module unloading is not yet supported.
///
const PROTECTED_DLL_INFO gProtectedModules[] =
{
    { u"ntdll.dll",             NAMEHASH_NTDLL },
    { u"kernel32.dll",          NAMEHASH_KERNEL32 },
    { u"kernelbase.dll",        NAMEHASH_KERNELBASE },
    { u"user32.dll",            NAMEHASH_USER32 },
    // Add any other modules here.
};


///
/// Setting a flag for the protection mask of a process will enable extended libraries protection.
///
const PROTECTED_DLL_INFO gProtectedNetModules[] =
{
    { u"ws2_32.dll",            NAMEHASH_WS2_32 },
    { u"wininet.dll",           NAMEHASH_WININET },
};


///
/// Full path to every DLL that must be protected.
///
const PROTECTED_DLL_INFO gProtectedWowModules[] =
{
    { u"ntdll.dll",             NAMEHASH_NTDLL },
    { u"wow64.dll",             NAMEHASH_WOW64 },
    { u"wow64win.dll",          NAMEHASH_WOW64WIN },
    { u"wow64cpu.dll",          NAMEHASH_WOW64CPU },

    // Add any other modules here.
};


static INTSTATUS
IntWinModHookPoly(
    _In_ PWIN_PROCESS_MODULE Module
    );


static BOOLEAN
IntWinModIsProtected(
    _In_ const WIN_PROCESS_MODULE *Module,
    _In_ const PROTECTED_DLL_INFO *ProtectedList,
    _In_ size_t ProtectedCount
    )
///
/// @brief Check if the given module is in the provided list of protected modules.
///
/// @param[in]  Module          The module to check.
/// @param[in]  ProtectedList   A list of protected DLL info.
/// @param[in]  ProtectedCount  Number of entries inside the ProtectedList.
///
/// @returns True if the Module in in ProtectedList, false otherwise.
///
{
    for (DWORD i = 0; i < ProtectedCount; i++)
    {
        if (MODULE_MATCH(Module, &ProtectedList[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}


static INTSTATUS
IntWinProcSendDllEvent(
    _In_ PWIN_PROCESS_MODULE Module,
    _In_ BOOLEAN Loaded
    )
///
/// @brief Send a DLL load/unload event to the integrator.
///
/// This function will send an #introEventModuleEvent event for the given module, if the modules events
/// #INTRO_OPT_EVENT_MODULES flag is enabled.
///
/// @param[in]  Module  The module that was just loaded or unloaded.
/// @param[in]  Loaded  True if the module has been loaded, false if it has been unloaded.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If Introcore is unloading or if the module events are not enabled.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If we already sent an event for this module.
///
{
    INTSTATUS status;
    PEVENT_MODULE_EVENT pModEvent;

    if (gGuest.UninitPrepared)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_MODULES))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (Loaded && Module->LoadEventSent)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!Loaded && Module->UnloadEventSent)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if ((NULL == Module->Path) || (0 == Module->VirtualBase) || (0 == Module->Size))
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    pModEvent = &gAlert.Module;
    memzero(pModEvent, sizeof(*pModEvent));

    pModEvent->Loaded = Loaded;
    pModEvent->Protected = Module->ShouldProtHooks || Module->ShouldProtUnpack;
    pModEvent->UserMode = TRUE;

    IntAlertFillWinUmModule(Module, &pModEvent->Module);

    IntAlertFillWinProcess(Module->Subsystem->Process, &pModEvent->CurrentProcess);

    status = IntNotifyIntroEvent(introEventModuleEvent, pModEvent, sizeof(*pModEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    if (Loaded)
    {
        Module->LoadEventSent = TRUE;
    }
    else
    {
        Module->UnloadEventSent = TRUE;
    }

    return status;
}


static INTSTATUS
IntWinProcSendAllDllEventsForSubsystem(
    _In_ PWIN_PROCESS_SUBSYSTEM Subsystem
    )
///
/// @brief Send a module load event for each loaded module inside a subsystem.
///
/// This function is called when we statically identify the modules of a process. It will iterate loaded module
/// inside the provided subsystem and it will send a DLL load event.
///
/// @param[in]  Subsystem   The subsystem for which we will send the DLL load events.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    LIST_ENTRY *list;
    PWIN_PROCESS_MODULE pMod;

    list = Subsystem->ProcessModules.Flink;
    while (list != &Subsystem->ProcessModules)
    {
        pMod = CONTAINING_RECORD(list, WIN_PROCESS_MODULE, Link);

        list = list->Flink;

        IntWinProcSendDllEvent(pMod, TRUE);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcSendAllDllEventsForProcess(
    _In_ PWIN_PROCESS_OBJECT Process
    )
///
/// @brief Send DLL load events for all modules loaded in all subsystems of a process.
///
/// @param[in]  Process The process for which we will send DLL load events.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    if (NULL != Process->Subsystemx86)
    {
        IntWinProcSendAllDllEventsForSubsystem(Process->Subsystemx86);
    }

    if (NULL != Process->Subsystemx64)
    {
        IntWinProcSendAllDllEventsForSubsystem(Process->Subsystemx64);
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinModCheckSpecialCases(
    _In_ PWIN_PROCESS_MODULE Module
    )
///
/// @brief Check if the process is DominoJava process.
///
/// This is a workaround for a DominoJava process which uses the j9jit and Java DLLs. If the loaded module
/// is a known DominoJava module, this function will set a flag in the Process (IsDominoJava).
///
/// @param[in]  Module  The module to be checked.
///
{
    PWIN_PROCESS_OBJECT pProc = Module->Subsystem->Process;

    // If the j9jit.dll is loaded and we are in a Java process, we may be in the Java IBM case
    // where certain VADs must be excepted at execution
    if (strstr_utf16(Module->Path->Name, u"j9jit") &&
        strstr(pProc->Name, "java"))
    {
        pProc->IsDominoJava = TRUE;
        pProc->FirstDominoJavaIgnored = FALSE;
    }
}


static INTSTATUS
IntWinModHandleMainModuleInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD ModuleBase,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) PBYTE Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief Callback called when the main module headers are present in physical memory.
///
/// This function will enable the unpacker on the main module, if the option is enabled.
///
/// @param[in]  Context         The module structure.
/// @param[in]  Cr3             The virtual address space.
/// @param[in]  ModuleBase      The guest virtual address of the swapped page (headers).
/// @param[in]  PhysicalAddress The physical address of the first swapped in page.
/// @param[in]  Data            Buffer containing the data.
/// @param[in]  DataSize        The size of the Data buffer.
/// @param[in]  Flags           Swa in flags - check out SWAPMEM_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If an invalid internal state is detected.
///
{
    INTSTATUS status;
    PWIN_PROCESS_MODULE pMod;
    PWIN_PROCESS_SUBSYSTEM pSubs;
    PWIN_PROCESS_OBJECT pProc;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    status = INT_STATUS_SUCCESS;

    pMod = (PWIN_PROCESS_MODULE)Context;

    pMod->HeadersSwapHandle = NULL;

    pSubs = pMod->Subsystem;
    if (NULL == pSubs)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    pProc = pSubs->Process;
    if (NULL == pProc)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    if ((Data[0] != 'M') || (Data[1] != 'Z'))
    {
        ERROR("[ERROR] Module is not a valid MZ image: %x%x, 0x%016llx:0x%016llx\n", Data[0], Data[1], ModuleBase,
              PhysicalAddress);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    TRACE("[MODULE] Main module for process %llx (subsystem %d) has loaded!\n",
          pProc->EprocessAddress, pSubs->SubsystemType);

    if (pMod->ShouldProtUnpack)
    {
        TRACE("[MODULE] Protecting module with base 0x%016llx -> 0x%016llx against unpacking.\n", ModuleBase, Cr3);

        status = IntWinModHookPoly(pMod);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModHookPoly failed: 0x%08x\n", status);
        }

        pProc->UnpackProtected = TRUE;
    }

    return status;
}


static int
IntWinModComparePaths(
    _In_ const WIN_PROCESS_MODULE *Module,
    _In_ const WCHAR *SystemDirPath,
    _In_ const WCHAR *TestModule
    )
///
/// @brief Tests whether the Module's path is the same as the TestModules' path inside the provided SystemDirPath.
///
/// @param[in]  Module          The module whose path is to be compared.
/// @param[in]  SystemDirPath   The system directory path.
/// @param[in]  TestModule      The path to be compared with the Module.
///
/// @returns -1 if the Module path is smaller, 0 if they are equal, 1 if the Module path is larger.
///
{
    WCHAR targetPath[MAX_PATH];
    size_t k, l;

    // Copy the directory path. They're both the same size, so it's safe to copy it entirely.
    memcpy(targetPath,
           SystemDirPath,
           MIN(sizeof(targetPath) - sizeof(WCHAR), (wstrlen(SystemDirPath) + 1) * sizeof(WCHAR)));

    // In case the memcpy didn't copy it
    targetPath[MAX_PATH - 1] = 0;

    // Append the module name.
    k = 0;
    while ((k < MAX_PATH) && (0 != targetPath[k]))
    {
        k++;
    }

    l = 0;
    while ((k + 1 < MAX_PATH) && (0 != TestModule[l]))
    {
        targetPath[k] = TestModule[l];

        k++, l++;
    }

    // Append the null terminator.
    targetPath[k] = 0;

    return wstrncasecmp_len(targetPath, Module->Path->Path, k, Module->Path->PathSize / 2);
}


static QWORD
IntWinModGetProtectionOptionForModule(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Get the protection options for provided module.
///
/// @param[in]  Module  The module object.
///
/// @retval The protection options for provided module.
///
{
    for (DWORD i = 0; i < ARRAYSIZE(gProtectedModules); i++)
    {
        if (MODULE_MATCH(Module, &gProtectedModules[i]))
        {
            return PROC_OPT_PROT_CORE_HOOKS;
        }
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtectedWowModules); i++)
    {
        if (MODULE_MATCH(Module, &gProtectedWowModules[i]))
        {
            return PROC_OPT_PROT_CORE_HOOKS;
        }
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtectedNetModules); i++)
    {
        if (MODULE_MATCH(Module, &gProtectedNetModules[i]))
        {
            return PROC_OPT_PROT_WSOCK_HOOKS;
        }
    }

    return 0;
}


static INTSTATUS
IntWinModIsKernelWriteInjection(
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ BOOLEAN *IsInjection
    )
///
/// @brief  Verifies if the current KM-UM write is due to an injection.
///
/// This function will parse the originator's stacktrace in order to find whether the detoured
/// MmCopyVirtualMemory is on the stack. If it is on the stack, we consider the current write
/// to be due to an injection.
///
/// @param[in]  Originator  The extracted originator of the current KM-UM write.
/// @param[out] IsInjection Will be set to TRUE if this write is considered to be due to an injection.
///
/// @returns    #INT_STATUS_SUCCESS on success or other appropiate INTSTATUS values in case of failure.
///
{
    INTSTATUS status;
    QWORD copyMemFunc = 0;

    status = IntDetGetFunctionAddressByTag(detTagProcInject, &copyMemFunc);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    for (DWORD trace = 0; trace < Originator->StackTrace.NumberOfTraces; trace++)
    {
        if (Originator->StackTrace.Traces[trace].CalledAddress == copyMemFunc)
        {
            *IsInjection = TRUE;

            return INT_STATUS_SUCCESS;
        }
    }

    *IsInjection = FALSE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinModFillDriverInjectionData(
    _In_ QWORD ReturnRip,
    _Inout_ EXCEPTION_KM_ORIGINATOR *Originator
    )
///
/// @brief  Fills the return driver data in the Originator when the write is caused by an injection
///         which was made by a driver.
/// This function will retrieve data about the driver which called ZwWriteVirtualMemory or other
/// APIs which result in KM-UM writes from MmCopyVirtualMemory. The data is filled into the Originator
/// exactly as in the case where the given driver is the return driver on the stack.
///
/// @param[in]      ReturnRip   The RIP where the ZwWriteVirtualMemory call returns.
/// @param[in, out] Originator  The Originator structure which will be filled with appropiate data
///                             based on the driver which caused the injection.
///
/// @returns    #INT_STATUS_SUCCESS on success or other appropiate INTSTATUS values in case of failure.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    KERNEL_DRIVER *pDrv;

    pDrv = IntDriverFindByAddress(ReturnRip);

    Originator->Injection.Kernel = TRUE;
    Originator->Return.Driver = pDrv;
    Originator->Return.Rip = ReturnRip;

    if (NULL != pDrv)
    {
        IMAGE_SECTION_HEADER sectionHeader = { 0 };

        Originator->Return.NameHash = pDrv->NameHash;
        Originator->Return.PathHash = pDrv->Win.PathHash;

        status = IntPeGetSectionHeaderByRva(pDrv->BaseVa,
                                            pDrv->Win.MzPeHeaders,
                                            (DWORD)(Originator->Return.Rip - pDrv->BaseVa),
                                            &sectionHeader);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntPeGetSectionHeaderByRva failed: 0x%08x\n", status);
            return status;
        }

        memcpy(Originator->Return.Section, sectionHeader.Name, sizeof(sectionHeader.Name));
    }
    else
    {
        Originator->Return.NameHash = INITIAL_CRC_VALUE;
        Originator->Return.PathHash = INITIAL_CRC_VALUE;
    }

    return status;
}


static INTSTATUS
IntWinModFillProcessInjectionData(
    _In_ QWORD CurrentThread,
    _Inout_ EXCEPTION_KM_ORIGINATOR *Originator
    )
///
/// @brief  Fills the originating process data in the Originator when the write is caused by an injection
///         which was made by a process in the current process.
///
/// When the process A injects into process B, the kernel will attach A's thread to the process B in order
/// to perform the requested writes. The thread owner remains A, so we'll consider the thread owner, that is
/// the original ETHREAD.Process field, to be the originating process.
///
/// @param[in]      CurrentThread   The thread in which context the current write occurs.
/// @param[in, out] Originator      The Originator structure which will be filled with appropiate data
///                                 based on the process which caused the injection.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If there is no process owning the current thread.   
///
{
    QWORD eprocess = 0;
    WIN_PROCESS_OBJECT *pProc = NULL;
    INTSTATUS status;

    // The injected process is attached in the current thread, but thread.Process should contain the
    // process that was performing the injection.
    status = IntKernVirtMemFetchWordSize(CurrentThread + WIN_KM_FIELD(Thread, Process), &eprocess);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
        return status;
    }

    pProc = IntWinProcFindObjectByEprocess(eprocess);
    if (NULL == pProc)
    {
        ERROR("[ERROR] IntWinProcFindObjectByEprocess failed for 0x%016llx\n", eprocess);
        return INT_STATUS_NOT_FOUND;
    }

    Originator->Injection.User = TRUE;
    Originator->Process.WinProc = pProc;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinModFillInjectionData(
    _Inout_ EXCEPTION_KM_ORIGINATOR *Originator
    )
///
/// @brief  Fills the originating caller which led to the detected injection and respectively the
///         current KM-UM writes.
///
/// On x64, this function will decide based on KTHREAD.PreviousMode whether the caller is a kernel
/// driver, in which case the return RIP is retrieved from a "fake TrapFrame", found inside the RBP
/// register, or a process, in which case we can get the current thread's owner process which is the
/// process which performed the injection in the first place. On x86, the algorithm is basically the
/// same, but for drivers the return can be fetched from the real TrapFrame from KTHREAD, constructed 
/// at the moment of the call.
///
/// @param[in, out] Originator      The Originator structure which will be filled with appropiate data
///                                 based on the driver or process which caused the injection.
///
/// @returns    #INT_STATUS_SUCCESS on success or other appropiate INTSTATUS values in case of failure.
///
{
    INTSTATUS status;

    if (gGuest.Guest64)
    {
        QWORD ethread = 0;
        BYTE previousMode = 0;

        status = IntWinThrGetCurrentThread(gVcpu->Index, &ethread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
            return status;
        }

        status = IntKernVirtMemRead(ethread + WIN_KM_FIELD(Thread, PreviousMode), 1, &previousMode, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        if (previousMode == 0)
        {
            QWORD realRsp = 0, realRet = 0;

            // On x64 there is a fake trapframe at Zw* calls which is only kept on the stack and in KTHREAD
            // is just another trapframe... This trapframe only contains some registers and the stack, so it
            // can't be mapped over a KTRAP_FRAME64. It is constructed in KiServiceInternal. For our purpose
            // it doesn't seem that Rbp is ever overwritten during a ZwWriteVirtualMemory, but maybe we should
            // see if we can make it more generic somehow...
            status = IntKernVirtMemFetchQword(gVcpu->Regs.Rbp + WIN_KM_FIELD(Ungrouped, RspOffsetOnZwCall), &realRsp);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
                return status;
            }

            status = IntKernVirtMemFetchQword(realRsp, &realRet);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
                return status;
            }

            status = IntWinModFillDriverInjectionData(realRet, Originator);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModFillDriverInjectionData failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntWinModFillProcessInjectionData(ethread, Originator);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModFillProcessInjectionData failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        KTRAP_FRAME32 trapFrame = { 0 };
        QWORD ethread = 0;
        DWORD trapFrameAddr;

        status = IntWinThrGetCurrentThread(gVcpu->Index, &ethread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
            return status;
        }

        status = IntKernVirtMemFetchDword(ethread + WIN_KM_FIELD(Thread, TrapFrame), &trapFrameAddr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchDword failed: 0x%08x\n", status);
            return status;
        }

        status = IntKernVirtMemRead(trapFrameAddr, sizeof(trapFrame), &trapFrame, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, trapFrame.Eip))
        {
            // It seems too easy, but the real return is always at trapFrame.HardwareEsp.
            // This happens because of the following code at KiServiceExit:
            //     nt!KiServiceExit + 0x15b:
            //     81b76439 8d6554          lea     esp, [ebp + 54h]
            //     81b7643c 5f              pop     edi
            //     81b7643d 5e              pop     esi
            //     81b7643e 5b              pop     ebx
            //     81b7643f 5d              pop     ebp
            //     81b76440 83c404          add     esp, 4
            //     81b76443 f744240401000000 test    dword ptr[esp + 4], 1
            //     81b7644b 7505            jne     nt!KiSystemCallExit2 (81b76452)  Branch
            // 
            //     nt!KiSystemCallExitBranch + 0x2:
            //     81b7644d 5a              pop     edx
            //     81b7644e 59              pop     ecx
            //     81b7644f 9d              popfd
            //     81b76450 ffe2            jmp     edx

            // So it can be seen that the stack will remain pointing to TrapFrame.HardwareEsp. Jumping to
            // the Zw* function, there will be a ret there, returning to the caller driver. So at HardwareEsp
            // there is always the caller driver.
            status = IntWinModFillDriverInjectionData(trapFrame.HardwareEsp, Originator);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModFillDriverInjectionData failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntWinModFillProcessInjectionData(ethread, Originator);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModFillProcessInjectionData failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}



static INTSTATUS
IntWinModHandleKernelWrite(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle writes inside a protected user-mode module from kernel-mode.
///
/// @param[in]  Context     The module (#PWIN_PROCESS_MODULE structure).
/// @param[in]  Hook        The GPA hook handle.
/// @param[in]  Address     The written guest physical address.
/// @param[out] Action      The desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION_REASON reason = introReasonUnknown;
    BOOLEAN informationOnly = FALSE;
    WIN_PROCESS_MODULE *pModule = (WIN_PROCESS_MODULE *)Context;
    WIN_PROCESS_OBJECT *pProcess = pModule->Subsystem->Process;
    BOOLEAN isInjection = FALSE;

    *Action = introGuestNotAllowed;

    STATS_ENTER(statsKmUmWrites);

    status = IntExceptKernelGetOriginator(&originator, EXCEPTION_KM_ORIGINATOR_OPT_FULL_STACK);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed with status: 0x%08x\n", status);

        reason = introReasonInternalError;
        informationOnly = TRUE;
    }

    status = IntWinModIsKernelWriteInjection(&originator, &isInjection);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinModIsKernelWriteInjection failed: 0x%08x\n", status);
    }

    if (isInjection)
    {
        status = IntWinModFillInjectionData(&originator);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModFillInjectionData failed: 0x%08x\n", status);
        }
    }

    status = IntExceptGetVictimEpt(Context,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeUmModule,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed with status: 0x%08x\n", status);

        reason = introReasonInternalError;
        informationOnly = TRUE;
    }

    if (informationOnly)
    {
        IntExceptKernelUserLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKmUm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsKmUmWrites);

    if (IntPolicyProcTakeAction(IntWinModGetProtectionOptionForModule(pModule), pProcess, Action, &reason))
    {
        EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;

        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idHooking;

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        IntAlertEptFillFromKmOriginator(&originator, pEptViol);
        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        pEptViol->Header.Flags = IntAlertProcGetFlags(IntWinModGetProtectionOptionForModule(pModule),
                                                      pModule->Subsystem->Process, reason, ALERT_FLAG_KM_UM);

        IntAlertFillWinProcessByCr3(pEptViol->Header.CpuContext.Cr3, &pEptViol->Header.CurrentProcess);

        IntAlertFillCodeBlocks(originator.Original.Rip, gVcpu->Regs.Cr3, FALSE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        IntAlertFillVersionInfo(&pEptViol->Header);

        pEptViol->Originator.Injection.User = originator.Injection.User;
        pEptViol->Originator.Injection.Kernel = originator.Injection.Kernel;

        IntAlertFillWinProcess(originator.Process.WinProc, &pEptViol->Originator.Process);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = INT_STATUS_SUCCESS;
    }

    IntPolicyProcForceBetaIfNeeded(IntWinModGetProtectionOptionForModule(pModule), pProcess, Action);

    return status;
}


static INTSTATUS
IntWinModHandleUserWrite(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle user-mode writes inside a protected user-mode module.
///
/// This function will check if the write being done inside a module is legitimate or not. Usually, in order
/// to determine this, we use the exceptions mechanism. However, there are a few optimizations here:
/// 1. OR [mem], 0 instruction is always allowed, as it used by the loader to prepare a section for writes;
/// 2. The first write inside each IAT entry is allowed without invoking the exceptions mechanism.
/// All other writes will go through the exceptions. If no exception matches, we will send an #introEventEptViolation
/// alert.
///
/// @param[in]  Context     The module (#PWIN_PROCESS_MODULE structure).
/// @param[in]  Hook        The GPA hook handle.
/// @param[in]  Address     The written guest physical address.
/// @param[out] Action      The desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    PWIN_PROCESS_MODULE pMod;
    PWIN_PROCESS_OBJECT pOriginatorProc;
    INTRO_ACTION_REASON reason;
    PIG_ARCH_REGS regs;
    EXCEPTION_UM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;
    DWORD iatidx, iatesz;

    status = INT_STATUS_SUCCESS;

    pMod = (PWIN_PROCESS_MODULE)Context;

    regs = &gVcpu->Regs;

    *Action = introGuestNotAllowed;
    reason = introReasonInternalError;

    if (regs->Cr3 != pMod->Subsystem->Process->Cr3)
    {
        const WIN_PROCESS_OBJECT *p = pMod->Subsystem->Process;
        const WIN_PROCESS_OBJECT *p2 = IntWinProcFindObjectByCr3(gVcpu->Regs.Cr3);

        WARNING("[WARNING] [SPECIAL-CASE] Process (pid: %d, eproc %llx, cr3 %llx, usercr3 %llx, name %s) "
                "is not the current one (current cr3 %llx, gva %llx, gpa %llx, ac %d)\n",
                p->Pid, p->EprocessAddress, p->Cr3, p->UserCr3, p->Name, regs->Cr3,
                gVcpu->Gla, gVcpu->Gpa, gVcpu->AccessSize);
        if (NULL != p2)
        {
            WARNING("[WARNING] [SPECIAL-CASE] Process (pid: %d, eproc %llx, cr3 %llx, usercr3 %llx, name %s) "
                    "is the current one!\n", p2->Pid, p2->EprocessAddress, p2->Cr3, p2->UserCr3, p2->Name);
        }
    }

    // Whitelist for ntdll!LdrpTouchPageForWrite.
    if ((gVcpu->AccessSize == 1) &&
        (gVcpu->Instruction.Instruction == ND_INS_OR) &&
        (gVcpu->Instruction.HasImm1) &&
        (gVcpu->Instruction.Immediate1 == 0))
    {
        *Action = introGuestAllowed;
        reason = introReasonAllowed;

        goto _cleanup_and_exit;
    }

    iatesz = (pMod->Is64BitModule ? 8 : 4);

    // White listing for IAT writes - we allow the first write that takes place in each IAT entry
    // if it is done from ntdll
    if ((pMod->IATBitmap != NULL) && (gVcpu->Gla >= pMod->VirtualBase + pMod->Cache->Info.IatRva) &&
        (gVcpu->Gla < pMod->VirtualBase + pMod->Cache->Info.IatRva + (QWORD)pMod->IATEntries * iatesz) &&
        (gVcpu->Regs.Rip >= pMod->Subsystem->NtdllBase &&
         gVcpu->Regs.Rip < pMod->Subsystem->NtdllBase + pMod->Subsystem->NtdllSize))
    {
        iatidx = (DWORD)(gVcpu->Gla - (pMod->VirtualBase + pMod->Cache->Info.IatRva)) / iatesz;

        if (pMod->IATBitmap[iatidx] == 0)
        {
            pMod->IATBitmap[iatidx]++;

            *Action = introGuestAllowed;
            reason = introReasonAllowed;

            goto _cleanup_and_exit;
        }
    }

    STATS_ENTER(statsExceptionsUser);

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    pOriginatorProc = pMod->Subsystem->Process;

    status = IntExceptUserGetOriginator(pOriginatorProc, TRUE, regs->Rip, &gVcpu->Instruction, &originator);
    if (status == INT_STATUS_STACK_SWAPPED_OUT)
    {
        *Action = introGuestRetry;
        status = INT_STATUS_SUCCESS;
        goto _send_notification;
    }
    else if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        *Action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _send_notification;
    }

    status = IntExceptGetVictimEpt(pMod,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeUmModule,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        *Action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, Action, &reason, introEventEptViolation);

_send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyProcTakeAction(IntWinModGetProtectionOptionForModule(pMod), pMod->Subsystem->Process, Action, &reason))
    {
        PEVENT_EPT_VIOLATION pEptViol = &gAlert.Ept;

        // First of all, send ALL the dll events.
        IntWinProcSendAllDllEventsForProcess(pOriginatorProc);

        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idHooking;

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        IntAlertEptFillFromUmOriginator(&originator, pEptViol);
        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        pEptViol->Header.Flags = IntAlertProcGetFlags(IntWinModGetProtectionOptionForModule(pMod),
                                                      pMod->Subsystem->Process, reason, 0);

        IntAlertFillWinProcessByCr3(pEptViol->Header.CpuContext.Cr3, &pEptViol->Header.CurrentProcess);

        IntAlertFillCodeBlocks(regs->Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        IntAlertFillVersionInfo(&pEptViol->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = INT_STATUS_SUCCESS;
    }

_cleanup_and_exit:
    IntPolicyProcForceBetaIfNeeded(IntWinModGetProtectionOptionForModule(pMod), pMod->Subsystem->Process, Action);

    return status;
}


INTSTATUS
IntWinModHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle writes inside a protected user-mode module wrapper. Will dispatch appropriately to either the kernel
/// or user write handler.
///
/// @param[in]  Context     The module (#PWIN_PROCESS_MODULE structure).
/// @param[in]  Hook        The GPA hook handle.
/// @param[in]  Address     The written guest physical address.
/// @param[out] Action      The desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    *Action = introGuestNotAllowed;

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, gVcpu->Regs.Rip))
    {
        return IntWinModHandleKernelWrite(Context, Hook, Address, Action);
    }
    else
    {
        return IntWinModHandleUserWrite(Context, Hook, Address, Action);
    }
}


static INTSTATUS
IntWinModHookModule(
    _In_ PWIN_PROCESS_MODULE Module
    )
///
/// @brief Hook a user-mode module against attacks.
///
/// This function will iterate all the sections inside the given module and all code & read-only sections
/// will be protected against writes using the EPT. Writes inside this module will be handled by
/// #IntWinModHandleWrite.
///
/// @param[in]  Module  The module to be protected.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If an invalid internal state is detected.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    DWORD sectionRva = 0;
    DWORD sectionCount = 0;
    DWORD i;
    PWIN_PROCESS_OBJECT pProc;
    IMAGE_SECTION_HEADER *sec;

    pProc = Module->Subsystem->Process;

    if (NULL == Module->Cache || NULL == Module->Cache->Headers)
    {
        ERROR("[ERROR] Invalid state where module doesn't has cache (%p) or headers!\n", Module->Cache);
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

#define MAX_IAT_ENTRIES    4096

    Module->IATEntries = Module->Cache->Info.IatSize / (Module->Is64BitModule ? 8 : 4);
    if (Module->IATEntries > MAX_IAT_ENTRIES)
    {
        WARNING("[WARNING] Module `%s` has %d IAT entries. Will use MAX_IAT_ENTRIES.",
                utf16_for_log(Module->Path->Name), Module->IATEntries);
        Module->IATEntries = MAX_IAT_ENTRIES;
    }


    if (Module->IATEntries != 0)
    {
        // Each entry will be initialized when that IAT entry will be written by the loader. The first write will be
        // allowed without checking the exceptions, all the other writes will go through the exceptions mechanism.
        Module->IATBitmap = HpAllocWithTag(Module->IATEntries, IC_TAG_IATB);
        if (NULL == Module->IATBitmap)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    status = IntHookObjectCreate(0, pProc->Cr3, &Module->HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        return status;
    }

    // At this point, there is no point in doing any verification, since they were already done
    // in the previous step (pre-hooking). The MzPeHeaders won't be present if they were invalid.
    status = IntPeListSectionsHeaders(Module->VirtualBase,
                                      Module->Cache->Headers,
                                      PAGE_SIZE,
                                      &sectionRva,
                                      &sectionCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeListSectionsHeaders failed with status: 0x%08x\n", status);
        return status;
    }

    TRACE("[MODULE] Protecting module '%s' loaded  at 0x%016llx\n",
          utf16_for_log(Module->Path->Path), Module->VirtualBase);

    sec = (IMAGE_SECTION_HEADER *)(Module->Cache->Headers + sectionRva);
    for (i = 0; i < sectionCount; i++, sec++)
    {
        if ((sec->Characteristics & IMAGE_SCN_MEM_WRITE) || (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            continue;
        }

        if ((QWORD)sec->VirtualAddress + sec->Misc.VirtualSize > Module->Vad->PageCount * PAGE_SIZE)
        {
            INFO("[INFO] Skipping section from VA 0x%08x, size 0x%08x, which is larger than VadSize 0x%016llx\n",
                 sec->VirtualAddress, sec->Misc.VirtualSize, Module->Vad->PageCount * PAGE_SIZE);
            continue;
        }

#ifdef DEBUG
        // The name of the section isn't always NULL terminated, let's make sure it is
        CHAR name[sizeof(sec->Name) + 1];
        memcpy(name, sec->Name, sizeof(sec->Name));
        name[sizeof(sec->Name)] = 0;

        TRACE("[MODULE] Protecting pageable region: 0x%016llx, VA space 0x%016llx, length %x Name `%s`\n",
              Module->VirtualBase + sec->VirtualAddress, pProc->Cr3, sec->Misc.VirtualSize, name);
#endif

        status = IntHookObjectHookRegion(Module->HookObject,
                                         pProc->Cr3,
                                         Module->VirtualBase + sec->VirtualAddress,
                                         ROUND_UP((SIZE_T)sec->Misc.VirtualSize, PAGE_SIZE),
                                         IG_EPT_HOOK_WRITE,
                                         IntWinModHandleWrite,
                                         Module,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
        }
    }

    Module->IsProtected = TRUE;

    Module->Subsystem->ProtectedModulesCount++;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinModUnHookModule(
    _In_ PWIN_PROCESS_MODULE Module
    )
///
/// @brief Remove the protection from the indicated module.
///
/// @param[in]  Module  The module to disable protection for.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is used.
///
{
    INTSTATUS status;

    if (NULL == Module)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // Remove the unpacker, if active.
    if (Module->ShouldProtUnpack && Module->Subsystem->Process->UnpackProtected)
    {
        status = IntUnpUnWatchVaSpacePages(Module->Subsystem->Process->Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUnpUnWatchVaSpacePages failed: 0x%08x\n", status);
        }
    }

    // Remove the protection, if any.
    if (NULL != Module->HookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Module->HookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
        }
    }

    if (NULL != Module->ModBlockObject)
    {
        status = IntWinModBlockRemoveBlockObject(Module->ModBlockObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModBlockRemoveBlockObject failed: 0x%08x\n", status);
        }
    }

    if (Module->IsProtected)
    {
        Module->Subsystem->ProtectedModulesCount--;
    }

    Module->IsProtected = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinModHandlePreInjection(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    )
///
/// @brief Module base page-fault pre-injection callback.
///
/// This callback is used as a pre-injection callback for the user-mode modules headers swap-in.
/// This function will check if the virtual address we inject a PF for is indeed valid (it has
/// a valid VAD assigned) inside the process space. If it does, the PF injection can be done.
/// If it doesn't, we cannot inject a PF for that address, as it would result in a process crash.
///
/// @param[in]  Context         The #PWIN_PROCESS_MODULE structure describing the module.
/// @param[in]  Cr3             The Cr3.
/// @param[in]  VirtualAddress  The address the PF is injected for.
///
/// @retval #INT_STATUS_SUCCESS If the address maps to valid VAD.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If a valid VAD does not exits. This will block the PF injection.
///
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);

    PWIN_PROCESS_MODULE pMod = (PWIN_PROCESS_MODULE)Context;
    if (NULL == pMod)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // We try to inject a #PF on this module. We have to make sure that the VAD corresponding to this module is already
    // inserted in the RB tree inside the guest! If we inject a #PF but the VAD is not queued yet, we will end up
    // crashing the process, because it would receive a #PF for an address which is still invalid (because the VAD
    // is not inserted in the tree yet!)
    if (!IntWinVadIsInTree(pMod->Vad))
    {
        LOG("[WINMODULE] The VAD 0x%016llx belonging to module %s seems to not be inside the tree yet, "
            "will postpone #PF...\n", pMod->Vad->VadGva, utf16_for_log(pMod->Path->Path));

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinModHandleModuleHeadersInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) PBYTE Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief Called as soon as the module headers are swapped in memory.
///
/// This function will be called whenever the loaded-module entry is present in the physical memory: either on
/// insertion inside the modules list, either after a page-fault is injected inside the guest.
/// This function will hook the module, if necessary.
///
/// @param[in]  Context         The module structure.
/// @param[in]  Cr3             The virtual address space.
/// @param[in]  VirtualAddress  The guest virtual address of the swapped page (headers).
/// @param[in]  PhysicalAddress The physical address of the first swapped in page.
/// @param[in]  Data            Buffer containing the data.
/// @param[in]  DataSize        The size of the Data buffer.
/// @param[in]  Flags           Swa in flags - check out SWAPMEM_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If an invalid internal state is detected.
///
{
    INTSTATUS status;
    PWIN_PROCESS_MODULE pMod;
    PWIN_PROCESS_SUBSYSTEM pSubs;
    PWIN_PROCESS_OBJECT pProc;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pMod = (PWIN_PROCESS_MODULE)Context;
    pMod->HeadersSwapHandle = NULL;

    pSubs = pMod->Subsystem;
    if (NULL == pSubs)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    pProc = pSubs->Process;
    if (NULL == pProc)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    status = IntWinUmModCacheSetHeaders(pMod, Data);

    if (INT_SUCCESS(status) && pProc->Protected && pMod->ShouldProtHooks)
    {
        TRACE("[MODULE] Protecting module with base 0x%016llx -> 0x%016llx against hooking.\n", VirtualAddress, Cr3);

        status = IntWinModHookModule(pMod);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModHookModule failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinModHandleModulePathInMemory(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ WINUM_PATH *Path
    )
///
/// @brief Handles a module path in memory.
///
/// This function gets called once the path of the indicated module is present in memory. Once we have the path, we
/// can:
/// - cache/reference the path;
/// - read & cache the module MZ/PE headers;
/// - enable protection on the module, if it's required;
/// - check if a suspicious module has been loaded (DoubleAgent).
///
/// @param[in]  Module  The module.
/// @param[in]  Path    The module path.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If an invalid internal state is encountered.
///
{
    PWIN_PROCESS_SUBSYSTEM pSubs;
    PWIN_PROCESS_OBJECT pProc;
    INTSTATUS status;

    pSubs = Module->Subsystem;
    if (NULL == pSubs)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    pProc = pSubs->Process;
    if (NULL == pProc)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    Module->Path = IntWinUmPathReference(Path);

    if (gGuest.Guest64 && (Module->Subsystem->SubsystemType == winSubsys32Bit))
    {
        // OK, we don't compare the entire length, we just want to see if the first part of the path matches.
        if (wstrncasecmp(Module->Path->Path, u"\\windows\\syswow64\\", CWSTRLEN(u"\\windows\\syswow64\\")) == 0)
        {
            Module->IsSystemModule = TRUE;
        }
    }
    else
    {
        // OK, we don't compare the entire length, we just want to see if the first part of the path matches.
        if (wstrncasecmp(Module->Path->Path, u"\\windows\\system32\\", CWSTRLEN(u"\\windows\\system32\\")) == 0)
        {
            Module->IsSystemModule = TRUE;
        }
    }

    pSubs->LoadedModulesCount++;

    TRACE("[MODULE] Module '%s' (%08x) just loaded at 0x%016llx in process '%s' (pid = %d)\n",
          utf16_for_log(Module->Path->Path), Module->Path->NameHash, Module->VirtualBase, pProc->Name, pProc->Pid);

    IntWinModCheckSpecialCases(Module);

    if (Module->VirtualBase == pProc->MainModuleAddress)
    {
        Module->IsMainModule = TRUE;

        pSubs->MainModuleLoaded = TRUE;

        if (!pProc->MainModuleLoaded)
        {
            pProc->MainModuleLoaded = TRUE;

            pProc->Path = IntWinUmPathReference(Module->Path);
        }
    }

    if (Module->IsMainModule && !pProc->SystemProcess)
    {
        if (NULL == IntWinProcGetProtectedInfoEx(Module->Path->Path, !!pProc->SystemProcess))
        {
            TRACE("[INFO] Application '%s' was not found among the protected ones, will remove protection.\n",
                  utf16_for_log(Module->Path->Path));

            status = IntWinProcUnprotect(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status);
            }

            return status;
        }
    }

    if (Module->IsSystemModule)
    {
        if ((Module->Path->NameHash == NAMEHASH_NTDLL) &&
            (0 == wstrcasecmp(Module->Path->Name, u"ntdll.dll")))
        {
            Module->Subsystem->NtdllBase = Module->VirtualBase;
            Module->Subsystem->NtdllSize = Module->Size;

            Module->Subsystem->NtdllLoadCount++;
        }
        else if ((Module->Path->NameHash == NAMEHASH_KERNEL32) &&
                 (0 == wstrcasecmp(Module->Path->Name, u"kernel32.dll")))
        {
            Module->Subsystem->Kernel32LoadCount++;
        }

        // For 32-bit processes on 64-bit guests we also need to check the WoW64 modules
        if ((winSubsys64Bit == pSubs->SubsystemType) && (pProc->Wow64Process))
        {
            if (IntWinModIsProtected(Module, gProtectedWowModules, ARRAYSIZE(gProtectedWowModules)))
            {
                Module->ShouldProtHooks = pSubs->Process->ProtCoreModules;
                Module->ShouldGetCache = TRUE;
            }
        }
        else
        {
            if (IntWinModIsProtected(Module, gProtectedModules, ARRAYSIZE(gProtectedModules)))
            {
                Module->ShouldProtHooks = pSubs->Process->ProtCoreModules;
                Module->ShouldGetCache = TRUE;
            }
            else if (IntWinModIsProtected(Module, gProtectedNetModules, ARRAYSIZE(gProtectedNetModules)))
            {
                Module->ShouldProtHooks = pSubs->Process->ProtWsockModules;
                Module->ShouldGetCache = TRUE;
            }
        }
    }

    if (pSubs->Process->ProtUnpack && Module->IsMainModule)
    {
        Module->ShouldProtUnpack = TRUE;
    }

    if (Module->ShouldGetCache)
    {
        IntWinUmModCacheGet(Module);

        if (NULL == Module->Cache)
        {
            ERROR("[ERROR] Module->Cache is NULL after IntWinUmModCacheGet!\n");
        }
        else
        {
            status = IntSwapMemReadData(pSubs->Process->Cr3,
                                        Module->VirtualBase,
                                        PAGE_SIZE,
                                        SWAPMEM_OPT_UM_FAULT,
                                        Module,
                                        0,
                                        IntWinModHandleModuleHeadersInMemory,
                                        IntWinModHandlePreInjection,
                                        &Module->HeadersSwapHandle);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                return status;
            }
        }
    }

    if (Module->ShouldProtUnpack)
    {
        status = IntSwapMemReadData(pSubs->Process->Cr3,
                                    Module->VirtualBase,
                                    2,
                                    SWAPMEM_OPT_UM_FAULT,
                                    Module,
                                    0,
                                    IntWinModHandleMainModuleInMemory,
                                    IntWinModHandlePreInjection,
                                    &Module->HeadersSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            return status;
        }
    }

    // Finally check if the current module might be loaded through double agent
    IntWinDagentCheckSuspiciousDllLoad(Module);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinModHandleLoadFromVad(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ const VAD *Vad
    )
///
/// @brief Handle a module load from a VAD.
///
/// This function gets called each time an VadImageMap VAD is being loaded. It will create a module
/// entry and it will activate protection on it, if needed.
///
/// @param[in]  Process The process.
/// @param[in]  Vad     The VAD being loaded.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    WIN_PROCESS_MODULE *pMod;

    if (Vad->PageCount * PAGE_SIZE > 0xFFFFFFFF)
    {
        ERROR("[ERROR] Module greater than 4GB!\n");

        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pMod = HpAllocWithTag(sizeof(*pMod), IC_TAG_MODU);
    if (NULL == pMod)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pMod->VirtualBase = Vad->StartPage;
    pMod->Size = (DWORD)(Vad->PageCount * PAGE_SIZE);
    pMod->StaticScan = Vad->StaticScan;
    pMod->Vad = Vad;

    if (gGuest.Guest64)
    {
        if (!Process->Wow64Process)
        {
            pMod->Subsystem = Process->Subsystemx64;
            pMod->Is64BitModule = TRUE;
        }
        else
        {
            // We're on 64 bit with wow64 process. We determine the subsystem using the module name. Inside the 64 bit
            // subsystem, the following modules will be loaded and possibly unloaded:
            // - /windows/system32/ntdll.dll
            // - /windows/system32/wow64win.dll
            // - /windows/system32/wow64.dll
            // - /windows/system32/wow64cpu.dll
            // - /windows/system32/kernel32.dll
            // - /windows/system32/user32.dll
            // All other modules will be 32 bit modules.
            // OK, we don't compare the entire length, we just want to see if the first part of the path matches.
            if (wstrncasecmp(Vad->Path->Path, u"\\windows\\system32\\", wstrlen(u"\\windows\\system32\\")) == 0)
            {
                pMod->Subsystem = Process->Subsystemx64;
                pMod->Is64BitModule = TRUE;
            }
            else
            {
                pMod->Subsystem = Process->Subsystemx86;
                pMod->Is64BitModule = FALSE;
            }
        }
    }
    else
    {
        pMod->Subsystem = Process->Subsystemx86;
        pMod->Is64BitModule = FALSE;
    }

    InsertTailList(&pMod->Subsystem->ProcessModules, &pMod->Link);

    status = IntWinModHandleModulePathInMemory(pMod, Vad->Path);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinModHandleModuleNameInMemory failed: 0x%08x\n", status);
        return status;
    }

    if (pMod->IsMainModule && Process->Wow64Process && (pMod->Subsystem == Process->Subsystemx86))
    {
        WIN_PROCESS_MODULE *pMod64;

        // If this was the main module, and we're inside a Wow64 process, we have to allocate a fresh entry
        // for the 64 bit subsystem.

        pMod64 = HpAllocWithTag(sizeof(*pMod64), IC_TAG_MODU);
        if (NULL == pMod64)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pMod64->Subsystem = Process->Subsystemx64;
        pMod64->VirtualBase = Vad->StartPage;
        pMod64->Size = (DWORD)(Vad->PageCount * PAGE_SIZE);
        pMod64->Vad = Vad;

        InsertTailList(&pMod64->Subsystem->ProcessModules, &pMod64->Link);

        status = IntWinModHandleModulePathInMemory(pMod64, Vad->Path);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModHandleModuleNameInMemory failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinModHandleUnload(
    _In_ PWIN_PROCESS_SUBSYSTEM Subsystem,
    _In_ QWORD VirtualBase
    )
///
/// @brief Handle a module unload from the given subsystem.
///
/// This function will handle an unload on the module located at address VirtualBase. This function will
/// search for a module loaded at the given address inside the given subsystem, it will remove it from the
/// list of loaded modules, it will remove protection from it and it will delete it.
///
/// @param[in]  Subsystem   The subsystem.
/// @param[in]  VirtualBase The base address of the module being unloaded.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If a module with the given address is not found.
///
{
    LIST_ENTRY *list;

    list = Subsystem->ProcessModules.Flink;
    while (list != &Subsystem->ProcessModules)
    {
        WIN_PROCESS_MODULE *pMod = CONTAINING_RECORD(list, WIN_PROCESS_MODULE, Link);
        list = list->Flink;

        if (pMod->VirtualBase == VirtualBase)
        {
            if ((pMod->Path->NameHash == NAMEHASH_NTDLL) &&
                (0 == wstrcasecmp(pMod->Path->Name, u"ntdll.dll")))
            {
                pMod->Subsystem->NtdllLoadCount--;
            }
            else if ((pMod->Path->NameHash == NAMEHASH_KERNEL32) &&
                     (0 == wstrcasecmp(pMod->Path->Name, u"kernel32.dll")))
            {
                pMod->Subsystem->Kernel32LoadCount--;
            }

            pMod->Subsystem->LoadedModulesCount--;

            // Don't spam with the unload event.

            RemoveEntryList(&pMod->Link);

            IntWinModUnHookModule(pMod);

            IntWinModRemoveModule(pMod);

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_NEEDED_HINT;
}


INTSTATUS
IntWinModHandleUnloadFromVad(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PVAD Vad
    )
///
/// @brief Handle a module unload.
///
/// This function is called whenever an VadImageMap VAD is deleted. Since those VADs describe modules, we will call
/// the unload function whenever such a VAD is destroyed.
///
/// @param[in]  Process The process owning the VAD.
/// @param[in]  Vad     The deleted Vad.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the VAD does not describe any known loaded module.
///
{
    INTSTATUS status = INT_STATUS_NOT_NEEDED_HINT;

    if (NULL != Process->Subsystemx86)
    {
        status = IntWinModHandleUnload(Process->Subsystemx86, Vad->StartPage);
        if (INT_STATUS_SUCCESS == status)
        {
            return status;
        }
    }

    if (NULL != Process->Subsystemx64)
    {
        status = IntWinModHandleUnload(Process->Subsystemx64, Vad->StartPage);
        if (INT_STATUS_SUCCESS == status)
        {
            return status;
        }
    }

    return status;
}


static BOOLEAN
IntWinModWriteValidHandler(
    _In_ QWORD Cr3,
    _In_ QWORD Address,
    _In_ void *Context
    )
///
/// @brief Checks if a write inside a code section is legitimate or not.
///
/// This function is used by the unpacker to check if a write is legitimate or note - if the write is inside a
/// code section but within the IAT, the write is deemed legitimate.
///
/// @param[in]  Cr3     The virtual address space.
/// @param[in]  Address The written guest virtual address.
/// @param[in]  Context The written module.
///
/// @returns True if the write is legitimate, false otherwise.
///
{
    PWIN_PROCESS_MODULE pMod;

    UNREFERENCED_PARAMETER(Cr3);

    if (NULL == Context)
    {
        return FALSE;
    }

    pMod = (PWIN_PROCESS_MODULE)Context;

    // No cache, bail out, assuming the write is OK.
    if (NULL == pMod->Cache)
    {
        return TRUE;
    }

    if ((Address - pMod->VirtualBase >= pMod->Cache->Info.IatRva) &&
        (Address - pMod->VirtualBase < (QWORD)pMod->Cache->Info.IatRva + pMod->Cache->Info.IatSize))
    {
        // The write is inside the IAT, we can ignore it for now.
        return TRUE;
    }

    return FALSE;
}


static INTSTATUS
IntWinModHookPoly(
    _In_ PWIN_PROCESS_MODULE Module
    )
///
/// @brief Hooks the given module against unpacks.
///
/// When an unpack is detected inside the given module, the #IntWinModPolyHandler callback will be called, which
/// will just send an alerts.
///
/// @param[in]  Module  The module to monitor against unpacks.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PBYTE pPage;
    IMAGE_SECTION_HEADER *sec;
    DWORD i;
    PWIN_PROCESS_OBJECT pProc;
    INTRO_PE_INFO peInfo = { 0 };

    pPage = NULL;

    pProc = Module->Subsystem->Process;

    status = IntVirtMemMap(Module->VirtualBase, PAGE_SIZE, pProc->Cr3, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
        return status;
    }

    status = IntPeValidateHeader(Module->VirtualBase, pPage, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    Module->Size = peInfo.SizeOfImage;

    sec = (IMAGE_SECTION_HEADER *)(pPage + peInfo.SectionOffset);
    for (i = 0; i < peInfo.NumberOfSections; i++, sec++)
    {
        DWORD secsize = sec->Misc.VirtualSize;

        // Skip sections larger than 4 MB.
        if (secsize > 4 * ONE_MEGABYTE)
        {
            continue;
        }

        // Check if this is a code section.
        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            (sec->Characteristics & IMAGE_SCN_CNT_CODE) ||
            (sec->Characteristics == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ)))
        {
            TRACE("[MODULE] Protecting pageable section: 0x%016llx, VA space 0x%016llx, length %x\n",
                  Module->VirtualBase + sec->VirtualAddress, pProc->Cr3, secsize);

            for (DWORD j = 0; j < secsize; j += 0x1000)
            {
                status = IntUnpWatchPage(pProc->Cr3,
                                         Module->VirtualBase + sec->VirtualAddress + j,
                                         IntWinModPolyHandler,
                                         IntWinModWriteValidHandler,
                                         Module);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntUnpWatchPage failed: 0x%08x\n", status);
                    break;
                }
            }
        }
    }

cleanup_and_exit:
    // The module may be partially protected against unpacking. This is not an issue, as the hooks will all be removed
    // when the process terminates (the unpacker works on a per/page basis). This only happens in case of errors.
    if (NULL != pPage)
    {
        IntVirtMemUnmap(&pPage);
    }

    return status;
}


INTSTATUS
IntWinModPolyHandler(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PINSTRUX Instrux,
    _In_ void *Context
    )
///
/// @brief Handle an unpack event for the indicated address.
///
/// This function is called when an unpack is detected on the indicated page. It will just send a
/// an unpack alert.
///
/// @param[in]  Cr3             The virtual address space the unpack took place in.
/// @param[in]  VirtualAddress  The guest virtual address where the unpack was detected.
/// @param[in]  Instrux         The instruction at VirtualAddress.
/// @param[in]  Context         A #PWIN_PROCESS_MODULE structure identifying the module.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    char text[ND_MIN_BUF_SIZE];
    PWIN_PROCESS_MODULE pMod;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pMod = (PWIN_PROCESS_MODULE)Context;

    if (pMod->UnpackAlertSent)
    {
        return INT_STATUS_SUCCESS;
    }

    status = NdToText(Instrux, VirtualAddress, ND_MIN_BUF_SIZE, text);
    if (!INT_SUCCESS(status))
    {
        strlcpy(text, "INVALID", sizeof(text));
    }

    LOG("[ALERT] [UNPACK DETECTED] Unpacked/decrypted page detected @ 0x%016llx:0x%016llx: %s\n", VirtualAddress, Cr3,
        text);

    pMod->UnpackAlertSent = TRUE;

    // Send the unpacker notification
    if (TRUE)
    {
        PEVENT_EPT_VIOLATION pEptViol = &gAlert.Ept;

        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = introGuestAllowed;
        pEptViol->HookStartPhysical = 0;
        pEptViol->HookStartVirtual = VirtualAddress & PAGE_MASK;
        pEptViol->Offset = VirtualAddress & PAGE_OFFSET;
        pEptViol->Victim.Type = (Cr3 != 0) ? introObjectTypeUmUnpack : introObjectTypeKmUnpack;
        pEptViol->Violation = IG_EPT_HOOK_EXECUTE;
        pEptViol->VirtualPage = VirtualAddress & PAGE_MASK;

        pEptViol->Header.CpuContext.Cpu = gVcpu->Index;
        pEptViol->Header.CpuContext.Rip = VirtualAddress;
        pEptViol->Header.CpuContext.Cr3 = Cr3;
        memcpy(pEptViol->Header.CpuContext.Instruction, text, sizeof(pEptViol->Header.CpuContext.Instruction));

        pEptViol->ExecInfo.Length = Instrux->Length;

        IntAlertFillWinProcess(pMod->Subsystem->Process, &pEptViol->Header.CurrentProcess);

        pEptViol->Header.MitreID = idSoftwarePacking;

        pEptViol->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_CORE_HOOKS,
                                                      pMod->Subsystem->Process, introReasonUnknown, 0);

        if (pMod->Subsystem->Process->SystemProcess)
        {
            pEptViol->Header.Flags |= ALERT_FLAG_SYSPROC;
        }

        IntAlertFillWinUmModule(pMod, &pEptViol->Victim.Module);

        IntAlertFillVersionInfo(&pEptViol->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinModRemoveModule(
    _In_ PWIN_PROCESS_MODULE Module
    )
///
/// @brief Removes a Windows module.
///
/// This function will cleanup all the resources associated with the indicated module, including:
/// - any swap handle for the module;
/// - the UM path cache entry;
/// - the headers cache entry;
/// Finally, the module will be freed.
/// NOTE: The module entry must be removed from any list/tree before calling this function.
/// NOTE: If the module was protected, protection must be removed from it before calling this. This
/// function must work for both protected and unprotected modules.
///
/// @param[in]  Module  The module to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;

    if (NULL == Module)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // Remove any pending swap operation.
    if (NULL != Module->HeadersSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Module->HeadersSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Module->HeadersSwapHandle = NULL;
    }

    if (NULL != Module->ExportsSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Module->ExportsSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Module->ExportsSwapHandle = NULL;
    }

    if (NULL != Module->SlackSpaceSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Module->SlackSpaceSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Module->SlackSpaceSwapHandle = NULL;
    }

    if (NULL != Module->MainModHeadersSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Module->MainModHeadersSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Module->MainModHeadersSwapHandle = NULL;
    }

    IntWinUmModCacheRelease(Module->Cache);

    if (Module->IsMainModule)
    {
        IntWinUmPathDereference(&Module->Subsystem->Process->Path);
        Module->Subsystem->Process->MainModuleLoaded = FALSE;
    }

    IntWinUmPathDereference(&Module->Path);

    if (NULL != Module->IATBitmap)
    {
        HpFreeAndNullWithTag(&Module->IATBitmap, IC_TAG_IATB);
    }

    HpFreeAndNullWithTag(&Module, IC_TAG_MODU);

    return INT_STATUS_SUCCESS;
}


void
IntWinModulesChangeProtectionFlags(
    _In_ PWIN_PROCESS_SUBSYSTEM Subsystem
    )
///
/// @brief Change the protection flags applied to the process modules that are currently loaded.
///
/// This function will iterate all the loaded modules inside the given subsystem and it will update the
/// protection policy on them. This function must be called when the process protection flags are modified.
///
/// @param[in]  Subsystem   The subsystem we update the protection in.
///
{
    PLIST_ENTRY pList;

    // we already have the list of modules, simply iterate it and change protection
    pList = Subsystem->ProcessModules.Flink;
    while (pList != &Subsystem->ProcessModules)
    {
        PWIN_PROCESS_MODULE pMod = CONTAINING_RECORD(pList, WIN_PROCESS_MODULE, Link);

        pList = pList->Flink;

        if (!pMod->IsSystemModule)
        {
            continue;
        }

        // If this is a 32-bit process on a 64-bit guest, we need to check if we have to update protection
        // for WoW64 modules
        if ((winSubsys64Bit == Subsystem->SubsystemType) && (Subsystem->Process->Wow64Process))
        {
            if (IntWinModIsProtected(pMod, gProtectedWowModules, ARRAYSIZE(gProtectedWowModules)))
            {
                if (pMod->ShouldProtHooks && !Subsystem->Process->ProtCoreModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS enabled -> disabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = FALSE;
                }
                else if (!pMod->ShouldProtHooks && Subsystem->Process->ProtCoreModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS disabled -> enabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = TRUE;
                }
                else
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS did not changed for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                }
            }
        }
        else
        {
            if (IntWinModIsProtected(pMod, gProtectedModules, ARRAYSIZE(gProtectedModules)))
            {
                if (pMod->ShouldProtHooks && !Subsystem->Process->ProtCoreModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS enabled -> disabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = FALSE;
                }
                else if (!pMod->ShouldProtHooks && Subsystem->Process->ProtCoreModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS disabled -> enabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = TRUE;
                }
                else
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_CORE_HOOKS did not changed for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                }
                break;
            }

            if (IntWinModIsProtected(pMod, gProtectedNetModules, ARRAYSIZE(gProtectedNetModules)))
            {
                if (pMod->ShouldProtHooks && !Subsystem->Process->ProtWsockModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_WSOCK_HOOKS enabled -> disabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = FALSE;
                }
                else if (!pMod->ShouldProtHooks && Subsystem->Process->ProtWsockModules)
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_WSOCK_HOOKS disabled -> enabled for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                    pMod->ShouldProtHooks = TRUE;
                }
                else
                {
                    TRACE("[WINMODULE] PROC_PROT_MASK_WSOCK_HOOKS did not changed for %s (Process %d)\n",
                          utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
                }
                break;
            }
        }

        // if this is the main module, check if unpack protection changed
        if (pMod->IsMainModule)
        {
            if (pMod->ShouldProtUnpack && !Subsystem->Process->ProtUnpack)
            {
                INTSTATUS status;

                TRACE("[WINMODULE] PROC_PROT_MASK_UNPACK enabled -> disabled for %s (Process %d). "
                      "Unwatching VA space 0x%016llx...\n", utf16_for_log(pMod->Path->Path),
                      Subsystem->Process->Pid, Subsystem->Process->Cr3);

                status = IntUnpUnWatchVaSpacePages(Subsystem->Process->Cr3);
                if (!INT_SUCCESS(status) && (INT_STATUS_NOT_FOUND != status))
                {
                    ERROR("[ERROR] IntUnpUnWatchVaSpacePages failed: 0x%x\n", status);
                }

                pMod->ShouldProtUnpack = FALSE;
            }
            else if (!pMod->ShouldProtUnpack && Subsystem->Process->ProtUnpack)
            {
                INTSTATUS status;

                TRACE("[WINMODULE] PROC_PROT_MASK_UNPACK disabled -> enabled for %s (Process %d)\n",
                      utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);

                status = IntWinModHookPoly(pMod);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinModHookPoly failed: 0x%x\n", status);
                }

                pMod->ShouldProtUnpack = TRUE;
            }
            else
            {
                TRACE("[WINMODULE] PROC_PROT_MASK_UNPACK did not changed for %s (Process %d)\n",
                      utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid);
            }
        }
        // if this is not the main module, check it is hooked and should be unhooked (or the other way)
        else if ((pMod->ShouldProtHooks) && (!pMod->IsProtected))
        {
            INTSTATUS status;

            TRACE("[WINMODULE] Protecting module with base 0x%016llx -> 0x%016llx against hooking.\n",
                  pMod->VirtualBase, Subsystem->Process->Cr3);

            status = IntWinModHookModule(pMod);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinModHookModule failed for %s (Process %d): 0x%x\n",
                      utf16_for_log(pMod->Path->Path), Subsystem->Process->Pid, status);
            }
        }
        else if ((!pMod->ShouldProtHooks) && (pMod->IsProtected))
        {
            TRACE("[WINMODULE] Removing protection for module with base 0x%016llx -> 0x%016llx\n",
                  pMod->VirtualBase, Subsystem->Process->Cr3);

            IntWinModUnHookModule(pMod);
        }
    }
}


PWIN_PROCESS_MODULE
IntWinUmModFindByAddress(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Gva
    )
///
/// @brief Searches for a user-mode module which contains the indicated guest virtual address.
///
/// NOTE: This function will search in all subsystems.
///
/// @param[in]  Process The process.
/// @param[in]  Gva     The guest virtual address we are searching for.
///
/// @returns A Windows module if Gva is found to point in one, or NULL if none is found.
///
{
    LIST_ENTRY *list;

    if (NULL != Process->Subsystemx64)
    {
        list = Process->Subsystemx64->ProcessModules.Flink;
        while (list != &Process->Subsystemx64->ProcessModules)
        {
            PWIN_PROCESS_MODULE pMod = CONTAINING_RECORD(list, WIN_PROCESS_MODULE, Link);
            list = list->Flink;

            if (IN_RANGE_LEN(Gva, pMod->VirtualBase, pMod->Size))
            {
                return pMod;
            }
        }
    }

    if (NULL != Process->Subsystemx86)
    {
        list = Process->Subsystemx86->ProcessModules.Flink;
        while (list != &Process->Subsystemx86->ProcessModules)
        {
            PWIN_PROCESS_MODULE pMod = CONTAINING_RECORD(list, WIN_PROCESS_MODULE, Link);
            list = list->Flink;

            if (IN_RANGE_LEN(Gva, pMod->VirtualBase, pMod->Size))
            {
                return pMod;
            }
        }
    }

    return NULL;
}
