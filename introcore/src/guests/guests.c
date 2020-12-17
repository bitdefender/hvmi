/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guests.h"
#include "callbacks.h"
#include "cr_protection.h"
#include "decoder.h"
#include "dtr_protection.h"
#include "exceptions.h"
#include "gpacache.h"
#include "hook.h"
#include "hook_cr.h"
#include "hook_dtr.h"
#include "hook_msr.h"
#include "hook_xcr.h"
#include "icache.h"
#include "lixapi.h"
#include "lixidt.h"
#include "lixkernel.h"
#include "lixvdso.h"
#include "memcloak.h"
#include "memtables.h"
#include "msr_protection.h"
#include "ptfilter.h"
#include "slack.h"
#include "swapgs.h"
#include "swapmem.h"
#include "unpacker.h"
#include "vasmonitor.h"
#include "vecore.h"
#include "visibility.h"
#include "winapi.h"
#include "winhal.h"
#include "winidt.h"
#include "wininfinityhook.h"
#include "winobj.h"
#include "winpfn.h"
#include "winselfmap.h"
#include "wintoken.h"
#include "winsud.h"
#include "winintobj.h"

///
/// @brief      The current guest state
///
/// Since we always have only one guest and all events are serialized, it is safe to have this as a global variable,
/// since no two threads will access it at the same time
///
GUEST_STATE gGuest = {0};

///
/// @brief      The state of the current VCPU
///
/// Since all events are serialized, we will always have only one current VCPU, it is safe to have this as a global
/// variable.
/// Set by every event handler. Will point to one entry from gGuest.VcpuArray.
///
VCPU_STATE *gVcpu = NULL;

/// @brief      The number of times initialization was tried
static DWORD gInitRetryCount = 0;

/// @brief      The last error reported.
static INTRO_ERROR_STATE gErrorState;

/// @brief      The last error-context reported.
static INTRO_ERROR_CONTEXT *gErrorStateContext;

/// @brief      Indicates that a syscall pattern belongs to a KPTI enabled OS.
#define SYSCALL_SIG_FLAG_KPTI 0x80000000

///
/// @brief      The syscall and sysenter signatures used to identify an OS
///
///
/// The signatures are plain binary chunks that must be found at the syscall entry point. 0x100 can be used as a
/// wild card in order to match anything.
///
PATTERN_SIGNATURE *gSysenterSignatures;
DWORD gSysenterSignaturesCount; ///< The number of entries in the #gSysenterSignatures array

///
/// @brief      The Cr2 write hook handle used for initialization
///
static HOOK_CR *gCr3WriteHook = NULL;


void
IntGuestSetIntroErrorState(
    _In_ INTRO_ERROR_STATE State,
    _In_opt_ INTRO_ERROR_CONTEXT *Context
    )
///
/// @brief Updates the value of the #gErrorState and the value of the #gErrorStateContext.
///
/// @param[in]  State       The type of the error.
/// @param[in]  Context     A context appropriate to the error.
///
{
    gErrorState = State;
    gErrorStateContext = Context;
}


INTRO_ERROR_STATE
IntGuestGetIntroErrorState(
    void
    )
///
/// @brief Gets the last reported error-state.
///
/// @retval Returns the type of the last reported error (#INTRO_ERROR_STATE).
///
{
    return gErrorState;
}


INTRO_ERROR_CONTEXT *
IntGuestGetIntroErrorStateContext(
    void
    )
///
/// @brief Gets the last reported error-context appropriate to the error-state.
///
/// @retval Returns the last reported error-context (#INTRO_ERROR_CONTEXT).
///
{
    return gErrorStateContext;
}


BOOLEAN
IntGuestShouldNotifyErrorState(
    void
    )
///
/// @brief      Checks if an event should be sent to the integrator.
///
/// @retval     True if the error-state event should be sent to the integrator.
///
{
    return gErrorState != intErrNone;
}


static void
IntGuestIsKptiActive(
    _In_ BYTE *SyscallBuffer,
    _In_ DWORD Size,
    _Out_ BOOLEAN *IsKptiActive
    )
///
/// @brief      Checks if the Syscall handler is specific to a System with KPTI enabled
///
/// It searches for Cr3 switches in the signature of the syscall handler.
///
/// @param[in]  SyscallBuffer   A buffer containing the code in the syscall handler
/// @param[in]  Size            The size of SyscallBuffer
/// @param[out] IsKptiActive    True if KPTI is active, False if it is not
///
{
    INTSTATUS status;

    *IsKptiActive = FALSE;

    for (DWORD it = 0; it < Size;)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstructionFromBuffer(SyscallBuffer + it,
                                                   Size - it,
                                                   gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B,
                                                   &instrux);
        if (!INT_SUCCESS(status))
        {
            it++;
            continue;
        }

        if (instrux.Instruction == ND_INS_MOV_CR &&
            ND_IS_OP_REG(&instrux.Operands[0], ND_REG_CR, (DWORD)gGuest.WordSize, NDR_CR3))
        {
            *IsKptiActive = TRUE;
            return;
        }

        it += instrux.Length;
    }
}


static INTSTATUS
IntGuestDetectOsSysCall(
    _In_ QWORD SyscallHandler,
    _Out_ INTRO_GUEST_TYPE *OsType,
    _Out_ BOOLEAN *KptiInstalled,
    _Out_ BOOLEAN *KptiActive
    )
///
/// @brief  Checks if any of the predefined syscall signatures match to the given syscall handler
///
/// @param[in]  SyscallHandler      The address of the syscall handler
/// @param[out] OsType              On success, the type of the detected operating system
/// @param[out] KptiInstalled       On success, True if the kernel has KPTI patches installed
/// @param[out] KptiActive          On success, True if KPTI mitigations are active
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if no signature matched
///
{
    INTSTATUS status;
    DWORD i, j;
    BYTE buffer[SIG_MAX_PATTERN] = {0};
    BOOLEAN found;

    *OsType = introGuestUnknown;
    *KptiInstalled = FALSE;
    *KptiActive = FALSE;

    status = IntKernVirtMemRead(SyscallHandler, sizeof(buffer), buffer, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", SyscallHandler, status);
        return status;
    }

    status = IntCamiLoadSection(CAMI_SECTION_HINT_SYSCALLS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCamiLoadSection failed: 0x%08x\n", status);
        return status;
    }

    for (i = 0; i < gSysenterSignaturesCount; i++)
    {
        found = TRUE;

        for (j = 0; j < gSysenterSignatures[i].Length; j++)
        {
            if (gSysenterSignatures[i].Pattern[j] != 0x100 && gSysenterSignatures[i].Pattern[j] != buffer[j])
            {
                found = FALSE;
                break;
            }
        }

        if (found)
        {
            TRACE("[INTRO-INIT] Found the syscall handler %d address at 0x%016llx\n", i, SyscallHandler);

            *OsType = gSysenterSignatures[i].SignatureId & 0xFF;
            *KptiInstalled = !!(gSysenterSignatures[i].SignatureId & SYSCALL_SIG_FLAG_KPTI);

            IntGuestIsKptiActive(buffer, sizeof(buffer), KptiActive);

            status = INT_STATUS_SUCCESS;
            goto _free_and_exit;
        }
    }

    LOG("Syscall/interrupt @0x%016llx handler not identified... Dumping %zu bytes from it!\n",
        SyscallHandler, sizeof(buffer));

    for (i = 0; i < sizeof(buffer); i += 8)
    {
        NLOG("%02x %02x %02x %02x %02x %02x %02x %02x\n", buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3],
             buffer[i + 4], buffer[i + 5], buffer[i + 6], buffer[i + 7]);
    }

    status = INT_STATUS_NOT_FOUND;

_free_and_exit:
    HpFreeAndNullWithTag(&gSysenterSignatures, IC_TAG_CAMI);

    return status;
}


static INTSTATUS
IntGuestDetectOs(
    _Out_ INTRO_GUEST_TYPE *OsType,
    _Out_ BOOLEAN *KptiInstalled,
    _Out_ BOOLEAN *KptiActive
    )
///
/// @brief      Detect the type of the currently running guest kernel
///
/// @param[out] OsType          On success, the type of the operating system
/// @param[out] KptiInstalled   On success, True if the kernel has KPTI patches installed
/// @param[out] KptiActive      On success, True if KPTI mitigations are active
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if the OS type was not detected
///
{
    INTSTATUS status;
    QWORD analyzeAddress[3] = {0};

    *OsType = introGuestUnknown;
    *KptiInstalled = FALSE;
    *KptiActive = FALSE;

    status = IntSyscallRead(IG_CURRENT_VCPU, NULL, &analyzeAddress[0]);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading SYSCALL MSRs: 0x%08x\n", status);
        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        return status;
    }

    status = IntSysenterRead(IG_CURRENT_VCPU, NULL, &analyzeAddress[1], NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading SYSENTER MSRs: 0x%08x\n", status);
        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        return status;
    }

    status = IntIdtGetEntry(IG_CURRENT_VCPU, VECTOR_DE, &analyzeAddress[2]);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading INT 0 handler: 0x%08x\n", status);
        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        return status;
    }

    for (DWORD l = 0; l < ARRAYSIZE(analyzeAddress); l++)
    {
        if (analyzeAddress[l] == 0)
        {
            continue;
        }

        status = IntGuestDetectOsSysCall(analyzeAddress[l], OsType, KptiInstalled, KptiActive);
        if (INT_SUCCESS(status))
        {
            TRACE("[INTRO-INIT] Found the syscall/interrupt handler address at %llx\n", analyzeAddress[l]);

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntGuestGetInfo(
    _Out_ PGUEST_INFO GuestInfo
    )
///
/// @brief      Get basic information about the guest
///
/// @param[out] GuestInfo   On success, will hold information about the guest
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if GuestInfo is NULL
/// @retval     #INT_STATUS_NOT_INITIALIZED if the type of the guest is not yet known
///
{
    if (NULL == GuestInfo)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    GuestInfo->Guest64 = gGuest.Guest64;
    GuestInfo->StartupTime = IG_INVALID_TIME;
    GuestInfo->OsVersion = gGuest.OSVersion;

    switch (gGuest.OSType)
    {
    case introGuestWindows:
    {
        QWORD time = 0;
        INTSTATUS status;

        GuestInfo->Type = introGuestWindows;
        GuestInfo->BuildNumber = gWinGuest->NtBuildNumberValue;

        status = IntWinGetStartUpTime(&time);
        if (INT_SUCCESS(status))
        {
            GuestInfo->StartupTime = time;
        }

        break;
    }

    case introGuestLinux:
        GuestInfo->Type = introGuestLinux;
        GuestInfo->BuildNumber = gLixGuest->Version.Value;
        break;

    default:
        return INT_STATUS_NOT_INITIALIZED;
    }

    return INT_STATUS_SUCCESS;
}


static PAGING_MODE
IntGuestGetPagingMode(
    _In_opt_ QWORD Efer,
    _In_opt_ QWORD Cr4,
    _In_opt_ QWORD Cr0
    )
///
/// @brief      Get the paging mode used by the guest on the current VCPU
///
/// @param[in]  Efer    The value of the IA 32 EFER MSR. If 0, it will be read from the current VCPU.
/// @param[in]  Cr4     The value of the Cr4 register. If 0, it will be read from the current VCPU.
/// @param[in]  Cr0     The value of the Cr0 register. If 0, it will be read from the current VCPU.
///
/// @returns    One of the #PAGING_MODE values
{
    INTSTATUS status;

    if (!Efer)
    {
        status = IntEferRead(gVcpu->Index, &Efer);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntEferRead failed: 0x%08x\n", status);
            return PAGING_NONE;
        }
    }

    if (!Cr4)
    {
        Cr4 = gVcpu->Regs.Cr4;
    }

    if (!Cr0)
    {
        Cr0 = gVcpu->Regs.Cr0;
    }

    if (0 != (Efer & EFER_LMA) && 0 != (Cr4 & CR4_LA57))
    {
        return PAGING_5_LEVEL_MODE;
    }
    else if (0 != (Efer & EFER_LMA))
    {
        return PAGING_4_LEVEL_MODE;
    }
    else if (0 != (Cr4 & CR4_PAE))
    {
        return PAGING_PAE_MODE;
    }
    else if (0 != (Cr0 & CR0_PG))
    {
        return PAGING_NORMAL_MODE;
    }

    return PAGING_NONE;
}


static INTSTATUS
IntGuestInitMemoryInfo(
    void
    )
///
/// @brief      Initializes gGuest.Mm
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    gGuest.Mm.Cr0 = gVcpu->Regs.Cr0;
    gGuest.Mm.Cr4 = gVcpu->Regs.Cr4;

    status = IntEferRead(gVcpu->Index, &gGuest.Mm.Efer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntEferRead failed: 0x%08x\n", status);
        return status;
    }

    gGuest.Guest64 = FALSE;
    gGuest.PaeEnabled = FALSE;
    gGuest.LA57 = FALSE;

    gGuest.Mm.Mode = IntGuestGetPagingMode(gGuest.Mm.Efer, gGuest.Mm.Cr4, gGuest.Mm.Cr0);

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode)
    {
        gGuest.Guest64 = TRUE;
        gGuest.PaeEnabled = TRUE;
        gGuest.LA57 = TRUE;
    }
    else if (PAGING_4_LEVEL_MODE == gGuest.Mm.Mode)
    {
        gGuest.Guest64 = TRUE;
        gGuest.PaeEnabled = TRUE;
    }
    else if (PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        gGuest.PaeEnabled = TRUE;
    }

    gGuest.WordSize = gGuest.Guest64 ? 8 : 4;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntGuestHandleCr3Write(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles Cr3 writes done by the guest. This is used to initialize the introspection engine.
///
/// In order to properly initialize the introspection engine, we need to start the process when the guest is executing
/// kernel code. There are multiple possible choices (for example, when the syscall MSR is written), but some of them
/// split the initialization flow in two big cases: either we catch the OS during a fresh boot, in which case a lot
/// of things become a lot easier; or, the OS may already be running, in which case some events will never trigger
/// (for example, the syscall MSR is not re-written by the OS once it booted). Writes to the Cr3 register are done
/// pretty frequently by the OS, so they are a good candidate for this.
/// Since keeping the Cr3 exits active once Introcore is properly loaded will lead to huge performance issues, once
/// we have enough information about the guest, this hook is removed and Cr3 exits are deactivated.
/// This hook is set by #IntGuestInit, using #gCr3WriteHook as the hook handle.
/// Since we may need multiple tries in order to be able to obtain all the needed information, this function will
/// retry it multiple times using #gInitRetryCount as a counter, for at maximum 32 times.
///
/// @param[in]  Context     Ignored
/// @param[in]  Cr          Ignored. We know this is a Cr3 write
/// @param[in]  OldValue    The old, original Cr3 value
/// @param[in]  NewValue    The value written to the cr
/// @param[out] Action      The action to be taken. This is always #introGuestAllowed because we don't want to block
///                         such an event, we just want to collect some information about the guest
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_SUPPORTED if the guest is using 5-level paging
/// @retval     #INT_STATUS_GUEST_OS_NOT_SUPPORTED is the type of the OS is not supported
/// @retval     #INT_STATUS_LOAD_ABORTED is loading was aborted by setting #gAbortLoad
///
{
#define MAX_INIT_RETRIES 32
    INTSTATUS status, status2;
    QWORD syscall = 0;
    QWORD sysenter = 0;
    INTRO_GUEST_TYPE osType;
    BOOLEAN bKptiInstalled, bKptiActive, bSameCr3;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Cr);

    *Action = introGuestAllowed;

    if (__unlikely(gGuest.GuestInitialized))
    {
        ERROR("[ERROR] Introspection is already initialized, this should not happen... Remove the hook!\n");

        IntHookCrRemoveHook(gCr3WriteHook);
        gCr3WriteHook = NULL;

        return INT_STATUS_SUCCESS;
    }

    if (!(gVcpu->Regs.Cr0 & CR0_PG))
    {
        return INT_STATUS_SUCCESS;
    }

    // Temporary initialize the gGuest.Mm (in case we want to do translations or anything)
    status = IntGuestInitMemoryInfo();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestInitMemoryInfo failed: 0x%08x\n", status);
        return status;
    }

    status = IntSyscallRead(IG_CURRENT_VCPU, NULL, &syscall);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSyscallRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntSysenterRead(IG_CURRENT_VCPU, NULL, &sysenter, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSysenterRead failed: 0x%08x\n", status);
        return status;
    }

    if (0 == syscall && 0 == sysenter)
    {
        return INT_STATUS_SUCCESS;
    }

    bSameCr3 = FALSE;

    switch (gGuest.Mm.Mode)
    {
    case PAGING_NONE:
        // Still in 16-bit mode, nothing to do yet
        return INT_STATUS_SUCCESS;

    case PAGING_NORMAL_MODE:
        bSameCr3 = (NewValue & CR3_LEGACY_NON_PAE_MASK) == (OldValue & CR3_LEGACY_NON_PAE_MASK);
        break;

    case PAGING_PAE_MODE:
        bSameCr3 = (NewValue & CR3_LEGACY_PAE_MASK) == (OldValue & CR3_LEGACY_PAE_MASK);
        break;

    case PAGING_4_LEVEL_MODE:
        bSameCr3 = (NewValue & CR3_LONG_MODE_MASK) == (OldValue & CR3_LONG_MODE_MASK);
        break;

    case PAGING_5_LEVEL_MODE:
        ERROR("[ERROR] Guest has activated LA57 mode, we don't support it yet!\n");

        IntNotifyIntroErrorState(intErrGuestNotSupported, NULL);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (bSameCr3)
    {
        return INT_STATUS_SUCCESS;
    }

    IntPauseVcpus();

    // This is the final MM info (the one which is supposed to be good)
    status = IntGuestInitMemoryInfo();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestInitMemoryInfo failed: %08x\n", status);
        goto _resume_and_leave;
    }

    LOG("[INTRO-INIT] Will try %d time to static init the guest on CPU %02d with EFER 0x%08llx and %s paging mode...\n",
        gInitRetryCount,
        gVcpu->Index, gGuest.Mm.Efer,
        gGuest.Mm.Mode == PAGING_5_LEVEL_MODE ? "5-level" :
        gGuest.Mm.Mode == PAGING_4_LEVEL_MODE ? "4-level" :
        gGuest.Mm.Mode == PAGING_PAE_MODE ? "PAE" :
        gGuest.Mm.Mode == PAGING_NORMAL_MODE ? "Normal" : "Invalid");

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        status = IntGetGprs(i, &gGuest.VcpuArray[i].Regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed on CPU %d: %08x\n", i, status);
            goto _resume_and_leave;
        }

        LOG("[INTRO-INIT] CPU %02d: CR0 = %08llx, CR3 = %016llx, CR4 = %08llx, RIP = %016llx\n",
            i, gGuest.VcpuArray[i].Regs.Cr0, gGuest.VcpuArray[i].Regs.Cr3,
            gGuest.VcpuArray[i].Regs.Cr4, gGuest.VcpuArray[i].Regs.Rip);
    }

    // Temporary, until we find the actual one (os-dependent)
    gGuest.Mm.SystemCr3 = gVcpu->Regs.Cr3;

    status = IntGuestDetectOs(&osType, &bKptiInstalled, &bKptiActive);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestDetectOs failed: 0x%08x\n", status);
        goto _resume_and_leave;
    }

    LOG("[INTRO-INIT] Identified OS type %s\n",
        osType == introGuestWindows ? "Windows" : "Linux");

    if (osType == introGuestWindows)
    {
        gGuest.KptiInstalled = bKptiInstalled;
        gGuest.KptiActive = bKptiActive;

        TRACE("[INTRO-INIT] Guest has KPTI installed: %d, enabled: %d\n",
              gGuest.KptiInstalled, gGuest.KptiActive);

        status = IntWinGuestNew();
    }
    else if (osType == introGuestLinux)
    {
        status = IntLixGuestNew();
    }
    else
    {
        status = INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        gGuest.DisableOnReturn = TRUE;
    }

    if (!INT_SUCCESS(status) || gGuest.DisableOnReturn)
    {
        goto _resume_and_leave;
    }

    status = IntCallbacksInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCallbacksInit failed: 0x%08x\n", status);

        gGuest.DisableOnReturn = TRUE;

        goto _resume_and_leave;
    }

    TRACE("[INTRO-INIT] Callbacks initialized successfully!\n");

    // Introcore is fully initialized, we can remove the cr3 write hook
    status2 = IntHookCrRemoveHook(gCr3WriteHook);
    if (INT_SUCCESS(status2))
    {
        gCr3WriteHook = NULL;
    }
    else
    {
        ERROR("[ERROR] IntHookCrRemoveHook failed: %08x\n", status2);
    }

_resume_and_leave:
    if ((++gInitRetryCount >= MAX_INIT_RETRIES) && !INT_SUCCESS(status))
    {
        ERROR("[ERROR] [CRITICAL] Tried %d times to init the introspection, bail out...\n", gInitRetryCount);

        gGuest.DisableOnReturn = TRUE;
    }

    if (gGuest.DisableOnReturn)
    {
        ERROR("[ERROR] An error occurred in init: %08x, %d. Will uninit the introspection!\n",
              status, gGuest.DisableOnReturn);

        if (gAbortLoad)
        {
            status = INT_STATUS_LOAD_ABORTED;
        }
    }

    IntResumeVcpus();

    return status;
#undef MAX_INIT_RETRIES
}


INTSTATUS
IntGuestInit(
    _In_ QWORD Options
    )
///
/// @brief      Initialize the given guest state
///
/// Any global, per guest initialization steps which do not depend on the guest type must be placed here.
/// Initialization steps which do depend on the guest type or version is done later in #IntWinGuestNew or
/// #IntLixGuestNew, where data about that guest is available.
/// This will initialize the hooking subsystem and will query basic guest information and hypervisor feature
/// availability. In order to properly initialize the guest, a Cr3 write hook is placed. Initialization will be done
/// on its handler: #IntGuestHandleCr3Write.
///
/// @param[in]  Options     Options to be used. See @ref group_options.
///
/// @retval     #INT_STATUS_SUCCESS in case of success. This means that initialization has been successfully started,
///             but it may still fail at further steps. The guest is not yet introspected.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
///
{
    INTSTATUS status;

    memzero(&gGuest, sizeof(gGuest));

    gInitRetryCount = 0;
    gGuest.CoreOptions.Current = Options;
    gGuest.CoreOptions.Original = Options;
    gGuest.KernelBetaDetections = 0 != (Options & INTRO_OPT_KM_BETA_DETECTIONS);
    gGuest.SysprocBetaDetections = 0 != (Options & INTRO_OPT_SYSPROC_BETA_DETECTIONS);
    gGuest.Mm.Mode = PAGING_NONE;

    gGuest.Initialized = TRUE;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_CPU_COUNT, NULL, &gGuest.CpuCount, sizeof(DWORD));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntQueryGuestInfo failed for feature CPU COUNT: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] CPU_COUNT = %d \n", gGuest.CpuCount);

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_TSC_SPEED, NULL, &gGuest.TscSpeed, sizeof(QWORD));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntQueryGuestInfo failed for feature TSC SPEED: 0x%08x\n", status);
        return status;
    }
    TRACE("[INTRO-INIT] TSC speed = 0x%016llx ticks/second\n", gGuest.TscSpeed);

    // Query for supported features.
    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_VE_SUPPORT, NULL, &gGuest.SupportVE, sizeof(BOOLEAN));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntQueryGuestInfo failed for feature #VE: 0x%08x\n", status);
        gGuest.SupportVE = FALSE;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_VMFUNC_SUPPORT, NULL, &gGuest.SupportVMFUNC, sizeof(BOOLEAN));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntQueryGuestInfo failed for feature VMFUNC: 0x%08x\n", status);
        gGuest.SupportVMFUNC = FALSE;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_SPP_SUPPORT, NULL, &gGuest.SupportSPP, sizeof(BOOLEAN));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntQueryGuestInfo failed for feature SPP: 0x%08x\n", status);
        gGuest.SupportSPP = FALSE;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_DTR_SUPPORT, NULL, &gGuest.SupportDTR, sizeof(BOOLEAN));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntQueryGuestInfo failed for feature DTR: 0x%08x\n", status);
        gGuest.SupportDTR = FALSE;
    }

    LOG("[INTRO-INIT] CPU/HV support: #VE: %s, VMFUNC: %s, SPP: %s, DTR events: %s\n",
        gGuest.SupportVE ? "yes" : "no", gGuest.SupportVMFUNC ? "yes" : "no",
        gGuest.SupportSPP ? "yes" : "no", gGuest.SupportDTR ? "yes" : "no");

    // Start initializing sub-components.
    gGuest.VcpuArray = HpAllocWithTag(gGuest.CpuCount * sizeof(VCPU_STATE), IC_TAG_CPUS);
    if (NULL == gGuest.VcpuArray)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _cleanup_and_exit;
    }

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        gGuest.VcpuArray[i].Index = i;
        // For now, assume that the guest is using this VCPU
        // For Windows guests this may change in IntWinGetActiveCpuCount
        gGuest.VcpuArray[i].Initialized = TRUE;
    }

    gVcpu = &gGuest.VcpuArray[IntGetCurrentCpu()];

    IntStatsInit();
    TRACE("[INTRO-INIT] Stats module initialized successfully!\n");

    status = IntHookInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] New Hook module initialized successfully!\n");

    status = IntHookMsrInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookMsrInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] MSR Hook module initialized successfully!\n");

    status = IntHookDtrInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookDtrInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] DTR Hook module initialized successfully!\n");

    status = IntHookCrInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] CR Hook module initialized successfully!\n");

    status = IntHookXcrInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookXcrInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] XCR Hook module initialized successfully!\n");

    status = IntIcCreate((PINS_CACHE *)&gGuest.InstructionCache, 512, 16, 512);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIcCreate failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] Instruction cache module initialized successfully!\n");

    // Init the GPA cache (on USER_MODE is bigger, because we have more memory)
#ifndef USER_MODE
    status = IntGpaCacheInit((PGPA_CACHE *)&gGuest.GpaCache, 256, 4);
#else
    status = IntGpaCacheInit((PGPA_CACHE *)&gGuest.GpaCache, 512, 8);
#endif // !USER_MODE
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] GPA cache module initialized successfully!\n");

    status = IntSwapMemInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] Swapmem module initialized successfully!\n");

    status = IntVasInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVasInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] VAS Monitor module initialized successfully!\n");

    status = IntExceptInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptInit failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }
    TRACE("[INTRO-INIT] Kernel-mode exception module initialized successfully!\n");

    // If both VE and PT options are set, choose only one, depending on whether #VE is active or not.
    if (!!(gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER) && !!(gGuest.CoreOptions.Current & INTRO_OPT_VE))
    {
        gGuest.PtFilterFlagRemoved = FALSE;

        if (gGuest.VeInitialized)
        {
            WARNING("[WARNING] Both INTRO_OPT_IN_GUEST_PT_FILTER and INTRO_OPT_VE are set, "
                    "will ignore INTRO_OPT_IN_GUEST_PT_FILTER, because #VE is initialized!\n");
            gGuest.CoreOptions.Current &= ~INTRO_OPT_IN_GUEST_PT_FILTER;
            gGuest.PtFilterFlagRemoved = TRUE;
        }
        else
        {
            WARNING("[WARNING] Both INTRO_OPT_IN_GUEST_PT_FILTER and INTRO_OPT_VE are set, "
                    "will ignore INTRO_OPT_VE, because #VE is NOT initialized!\n");
            gGuest.CoreOptions.Current &= ~INTRO_OPT_VE;
        }
    }

    // After we initialized all the subsystems, hook CR3 writes so we can gracefully init the rest
    status = IntHookCrSetHook(3, 0, IntGuestHandleCr3Write, NULL, &gCr3WriteHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrSetHook failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    status = INT_STATUS_SUCCESS;

_cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntGuestUninit();
    }

    return status;
}


void
IntGuestPrepareUninit(
    void
    )
///
/// @brief  Prepares introcore to be unloaded
///
/// Disables most subsystems (cancels pending agents, disables protections, etc), but does not yet modify the guest
/// memory, so any hooks placed by Introcore will still be present. This allows us to more safely clean up the
/// guest state.
/// After this function exits, #GUEST_STATE.UninitPrepared will be set to True. If the initialization Cr3 hook is still
/// active, it will be disabled.
///
{
    if (gGuest.UninitPrepared)
    {
        return;
    }

    IntVeDumpVeInfoPages();

    IntCamiClearUpdateBuffer();

    IntGuestUpdateCoreOptions(0);

    IntDetDisableAllHooks();

    IntAgentDisablePendingAgents();

    IntMtblDisable();

    IntSwapgsDisable();

    if (gGuest.OSType == introGuestWindows)
    {
        IntWinObjCleanup();

        IntWinGuestCancelKernelRead();
    }

    if (gCr3WriteHook)
    {
        IntHookCrRemoveHook(gCr3WriteHook);
        gCr3WriteHook = NULL;
    }

    IntHookCommitAllHooks();

    gGuest.UninitPrepared = TRUE;
}


void
IntGuestUninit(
    void
    )
///
/// @brief      Completely unloads the introspection engine
///
/// Any generic unload routine must be placed here. Guest specific unload steps must be placed in #IntWinGuestUninit or
/// #IntLixGuestUninit.
/// This function will call the guest-specific routines, then will disable every introcore subsystem and remove any
/// code or data injected by introcore inside the guest (detours, agents, etc).
/// After this function returns #GUEST_STATE.VcpuArray, #gWinGuest, and #gLixGuest are no longer valid and the entire
/// #gGuest state is zeroed.
///
{
    // We dump some statistics to know what happened while Introcore was running.
    IntDetDumpDetours();
    IntStatsDumpAll();

    if (gCr3WriteHook)
    {
        IntHookCrRemoveHook(gCr3WriteHook);
        gCr3WriteHook = NULL;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        TRACE("[INTRO-UNINIT] Uninit the Windows guest...\n");
        IntWinGuestUninit();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        TRACE("[INTRO-UNINIT] Uninit the Linux guest...\n");
        IntLixGuestUninit();
    }

    TRACE("[INTRO-UNINIT] Uninit #VE...\n");
    IntVeUnInit();

    TRACE("[INTRO-UNINIT] Uninit exceptions...\n");
    IntExceptUninit();

    TRACE("[INTRO-UNINIT] Uninit integrity...\n");
    IntIntegrityUninit();

    TRACE("[INTRO-UNINIT] Uninit VAS monitor...\n");
    IntVasUnInit();

    TRACE("[INTRO-UNINIT] Uninit memory tables...\n");
    IntMtblUninit();

    TRACE("[INTRO-UNINIT] Uninit SWAPGS mitigations...\n");
    IntSwapgsUninit();

    TRACE("[INTRO-UNINIT] Uninit detours-guest...\n");
    IntDetUninit();

    TRACE("[INTRO-UNINIT] Uninit slack...\n");
    IntSlackUninit();

    TRACE("[INTRO-UNINIT] Uninit instruction cache...\n");
    if (NULL != gGuest.InstructionCache)
    {
        IntIcDestroy((PINS_CACHE *)&gGuest.InstructionCache);
    }

    TRACE("[INTRO-UNINIT] Uninit memcloak...\n");
    IntMemClkUnInit();

    TRACE("[INTRO-UNINIT] Uninit swapmem...\n");
    IntSwapMemUnInit();

    if (gGuest.OSType == introGuestWindows)
    {
        // Page-lock uninit. Do it after detours and memclk (they have references to it)
        TRACE("[INTRO-UNINIT] Uninit windows pfn locks...\n");
        IntWinPfnUnInit();
    }

    TRACE("[INTRO-UNINIT] Uninit unpack...\n");
    IntUnpUninit();

    TRACE("[INTRO-UNINIT] Uninit new hooks...\n");
    IntHookUninit();

    TRACE("[INTRO-UNINIT] Uninit hooker-msr...\n");
    IntHookMsrUninit();

    TRACE("[INTRO-UNINIT] Uninit hooker-dtr...\n");
    IntHookDtrUninit();

    TRACE("[INTRO-UNINIT] Uninit hooker-cr...\n");
    IntHookCrUninit();

    TRACE("[INTRO-UNINIT] Uninit hooker-xcr...\n");
    IntHookXcrUninit();

    TRACE("[INTRO-UNINIT] Uninit GPA cache...\n");
    if (NULL != gGuest.GpaCache)
    {
        IntGpaCacheUnInit((PGPA_CACHE *)&gGuest.GpaCache);
    }

    // The callbacks must be uninitialized AFTER the detours. Otherwise, we may end up with a pending event
    // after we have removed the callbacks but before we have removed the detours. This way, we would erroneously
    // emulate the attempt instead of faking the original content.
    TRACE("[INTRO-UNINIT] Uninit callbacks...\n");
    IntCallbacksUnInit();

    TRACE("[INTRO-UNINIT] Free cami protected processes array ...\n");
    IntCamiProtectedProcessFree();

    if (NULL != gGuest.VcpuArray)
    {
        HpFreeAndNullWithTag(&gGuest.VcpuArray, IC_TAG_CPUS);
    }

    gWinGuest = NULL;
    gLixGuest = NULL;

    TRACE("Calling the notification callback...\n");

    IntNotifyIntroInactive();

    memzero(&gGuest, sizeof(gGuest));

    TRACE("All done!\n");
}


static BOOLEAN
IntGuestIsSafeToDisable(
    void
    )
///
/// @brief      Checks if it is safe to unload
///
/// If no guest threads are executing or returning to code injected by introcore inside the guest, it is safe to
/// unload the introspection engine now.
///
/// @retval     True if it is safe to unload
/// @retval     False if it is not safe to unload
///
{
    INTSTATUS status;
    AG_WAITSTATE agWaitState;
    DWORD agTag;

    agWaitState = IntAgentGetState(&agTag);
    if (agWaitState != agNone)
    {
        WARNING("[SAFENESS] We have a %s agent with tag %u!\n",
                agWaitState == agActive ? "Active" : "Waiting", agTag);
        return FALSE;
    }

    status = IntThrSafeCheckThreads(THS_CHECK_ONLY | THS_CHECK_DETOURS | THS_CHECK_MEMTABLES | THS_CHECK_TRAMPOLINE |
                                    THS_CHECK_SWAPGS);
    if (INT_STATUS_CANNOT_UNLOAD == status)
    {
        return FALSE;
    }

    return TRUE;
}


INTSTATUS
IntGuestDisableIntro(
    _In_ QWORD Flags
    )
///
/// @brief      Disables and unloads the introspection engine.
///
/// This will deactivate every Introcore subsystem and remove any hooks placed by Introcore. This is done with all
/// the VCPUs paused.
///
/// @param[in]  Flags   Flags controlling the disable operation. Can be 0 or #IG_DISABLE_IGNORE_SAFENESS. If
///                     #IG_DISABLE_IGNORE_SAFENESS is used, Introcore will forcibly unload even it is not safe to
///                     do that at the moment. This may leave the guest in an unstable state.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_CANNOT_UNLOAD if Introcore can not unload.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    IntPauseVcpus();

    if (gGuest.EnterHibernate)
    {
        LOG("Introcore shutdown requested while the guest is transitioning into hibernate...\n");
    }

    if (gGuest.BugCheckInProgress)
    {
        Flags |= IG_DISABLE_IGNORE_SAFENESS;
    }

    if (IntGuestShouldNotifyErrorState())
    {
        IntNotifyIntroErrorState(IntGuestGetIntroErrorState(), IntGuestGetIntroErrorStateContext());
        IntGuestSetIntroErrorState(intErrNone, NULL);
    }

    IntGuestPrepareUninit();

    // Unless the caller specified to ignore it, we check all the threads so they won't return into our
    // detours/memtables/agents/etc. stubs.
    if (!!(Flags & IG_DISABLE_IGNORE_SAFENESS))
    {
        LOG("[INFO] Ignore safeness!\n");
        goto do_uninit;
    }

    if (!IntGuestIsSafeToDisable())
    {
        LOG("[INFO] It's not safe to unload yet!\n");

        status = INT_STATUS_CANNOT_UNLOAD;
        goto resume_and_exit;
    }

    if (gGuest.OSType == introGuestLinux)
    {
        IntLixGuestUninitGuestCode();

        if (IntLixGuestDeployUninitAgent())
        {
            status = INT_STATUS_CANNOT_UNLOAD;
            goto resume_and_exit;
        }
    }

do_uninit:
    IntGuestUninit();

resume_and_exit:
    IntResumeVcpus();

    return status;
}


INTSTATUS
IntGuestPreReturnCallback(
    _In_ DWORD Options
    )
///
/// @brief      Handles all the operations that must be done before returning from a VMEXIT event handler
///
/// Certain operations can not be done while we are inside one of our own callbacks, so they are delegated here.
///
/// @param[in]  Options     A combination of #PRE_RET_OPTIONS values that control the operations done
///
/// @retval     #INT_STATUS_SUCCESS always
///
{
    INTSTATUS status;
    BOOLEAN skipAgentActivation = FALSE;

    if (__unlikely((Options & POST_RETRY_PERFAGENT) && gGuest.PtFilterWaiting))
    {
        LOG("[PTCORE] Will try to reinject the PT Filter...\n");
        status = IntPtiInjectPtFilter();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPtiInjectPtFilter failed: 0x%08x\n", status);
        }
        else
        {
            gGuest.PtFilterWaiting = FALSE;
            skipAgentActivation = TRUE;
            LOG("[PTCORE] PT Filter was re-injected with success!\n");
        }
    }
    else if (__unlikely((Options & POST_RETRY_PERFAGENT) && gGuest.VeAgentWaiting))
    {
        LOG("[VECORE] Will try to reinject the #VE Agent...\n");
        status = IntVeDeployAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeDeployAgent failed: 0x%08x\n", status);
        }
        else
        {
            gGuest.VeAgentWaiting = FALSE;
            skipAgentActivation = TRUE;
            LOG("[VECORE] The #VE Agent was re-injected with success!\n");
        }
    }

    if (!skipAgentActivation)
    {
        // Always try to wake up a pending agent, if there are any, except for when we successfully re-injected the PT
        // Filter.
        status = IntAgentActivatePendingAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentActivatePendingAgent failed: 0x%08x\n", status);
        }
    }

    if (__likely(Options & POST_COMMIT_MEM))
    {
        status = IntHookCommitAllHooks();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookCommitAllHooks failed: 0x%08x\n", status);
        }
    }

    if (Options & POST_COMMIT_MSR)
    {
        status = IntHookMsrCommit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookMsrCommit failed: 0x%08x\n", status);
        }
    }

    if (Options & POST_COMMIT_DTR)
    {
        status = IntHookDtrCommit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookDtrCommit failed: 0x%08x\n", status);
        }
    }

    if (Options & POST_COMMIT_CR)
    {
        status = IntHookCrCommit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookCrCommit failed: 0x%08x\n", status);
        }
    }

    if (Options & POST_COMMIT_XCR)
    {
        status = IntHookXcrCommit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookXcrCommit failed: 0x%08x\n", status);
        }
    }

    if (__likely(Options & POST_INJECT_PF))
    {
        status = IntSwapMemInjectPendingPF();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemInjectPendingPF failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


void
IntGuestUpdateShemuOptions(
    _In_ QWORD NewOptions
    )
///
/// @brief      Update shemu options
///
/// This will set the gGuest.ShemuOptions based on NewOptions and will enable or disable any shemu feature
/// that was toggled by the new options.
///
/// @param[in]  NewOptions  The new options to be used.
///
{
    // We must save them in case an update comes which removes a previously set ForceOff (and the NewOptions set it too)
    gGuest.ShemuOptions.Original = NewOptions;

    NewOptions &= ~gGuest.ShemuOptions.ForceOff;

    if (NewOptions == gGuest.ShemuOptions.Current)
    {
        return;
    }

    LOG("[DYNOPT] Change shemu options from %llx to %llx\n", gGuest.ShemuOptions.Current, NewOptions);

    gGuest.ShemuOptions.Current = NewOptions;
}


void
IntGuestUpdateCoreOptions(
    _In_ QWORD NewOptions
    )
///
/// @brief      Updates Introcore options
///
/// This will set the gGuest.CoreOptions based on NewOptions and will enable or disable any protection or service
/// that was toggled by the new options. These operations are done with the VCPUs paused.
///
/// @param[in]  NewOptions  The new options to be used. See @ref group_options for valid values
///
{
    // We must save them in case an update comes which removes a previously set ForceOff (and the NewOptions set it too)
    gGuest.CoreOptions.Original = NewOptions;

    NewOptions &= ~gGuest.CoreOptions.ForceOff;

    if (NewOptions == gGuest.CoreOptions.Current)
    {
        return;
    }

    if (gGuest.UninitPrepared)
    {
        WARNING("[WARNING] Cannot modify options now, an uninit is pending!\n");
        return;
    }

    if (!!(NewOptions & INTRO_OPT_IN_GUEST_PT_FILTER) && !!(NewOptions & INTRO_OPT_VE))
    {
        gGuest.PtFilterFlagRemoved = FALSE;

        if (gGuest.VeInitialized)
        {
            WARNING("[WARNING] Both INTRO_OPT_IN_GUEST_PT_FILTER and INTRO_OPT_VE are set, will ignore"
                    "INTRO_OPT_IN_GUEST_PT_FILTER, because #VE is initialized!\n");
            NewOptions &= ~INTRO_OPT_IN_GUEST_PT_FILTER;
            gGuest.PtFilterFlagRemoved = TRUE;
        }
        else
        {
            WARNING("[WARNING] Both INTRO_OPT_IN_GUEST_PT_FILTER and INTRO_OPT_VE are set, will ignore INTRO_OPT_VE, "
                    "because #VE is NOT initialized!\n");
            NewOptions &= ~INTRO_OPT_VE;
        }
    }

    LOG("[DYNOPT] Change core options from %llx to %llx\n", gGuest.CoreOptions.Current, NewOptions);

    gGuest.CoreOptions.Current = NewOptions;
    gGuest.KernelBetaDetections = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_KM_BETA_DETECTIONS);
    gGuest.SysprocBetaDetections = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_SYSPROC_BETA_DETECTIONS);

    // We don't know what os this is, or we can't apply options yet... we can bail out now.
    if (!gGuest.GuestInitialized || !gGuest.SafeToApplyOptions)
    {
        return;
    }

    IntPauseVcpus();

    if (introGuestWindows == gGuest.OSType)
    {
        // Enable or disable detours, depending on active options.
        IntWinApiUpdateHooks();

        // Enable or disable driver object and fast I/O dispatch table hooks.
        // Covers INTRO_OPT_PROT_KM_DRVOBJ.
        IntWinDrvObjUpdateProtection();

        // Enable or disable nt, hal, core, av and xen drivers protection.
        // Covers INTRO_OPT_PROT_KM_NT, INTRO_OPT_PROT_KM_SSDT, INTRO_OPT_PROT_KM_HAL,
        // INTRO_OPT_PROT_KM_NT_DRIVERS, INTRO_OPT_PROT_KM_AV_DRIVERS and INTRO_OPT_PROT_KM_XEN_DRIVERS
        IntWinDrvUpdateProtection();

        // Enable or disable hal dispatch table, hal heap and hal interrupt controller protection.
        // Covers INTRO_OPT_PROT_KM_HAL_DISP_TABLE, INTRO_OPT_PROT_KM_HAL_HEAP_EXEC and INTRO_OPT_PROT_KM_HAL_INT_CTRL.
        IntWinHalUpdateProtection();

        // Enable or disable process protection.
        // Covers INTRO_OPT_PROT_UM_MISC_PROCS and INTRO_OPT_PROT_UM_SYS_PROCS.
        IntWinProcUpdateProtection();

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_MSR_SYSCALL)
        {
            IntMsrSyscallProtect();
        }
        else
        {
            IntMsrSyscallUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDT)
        {
            IntWinIdtProtectAll();
        }
        else
        {
            IntWinIdtUnprotectAll();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CR4)
        {
            IntCr4Protect();
        }
        else
        {
            IntCr4Unprotect();
        }

        // INTRO_OPT_PROT_KM_SYSTEM_CR3 and INTRO_OPT_PROT_KM_TOKEN_PTR are tested directly in the timer, so no need
        // to do anything here.
        // All the other options are not protection related and can be toggled as well.

        // First of, schedule agents removal.
        if (!(gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER))
        {
            IntPtiRemovePtFilter(0);
        }

        if (!(gGuest.CoreOptions.Current & INTRO_OPT_VE))
        {
            IntVeRemoveAgent(0);
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER)
        {
            IntPtiInjectPtFilter();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_VE)
        {
            IntVeDeployAgent();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SELF_MAP_ENTRY)
        {
            IntWinSelfMapEnableSelfMapEntryProtection();
        }
        else
        {
            IntWinSelfMapDisableSelfMapEntryProtection();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDTR)
        {
            IntIdtrProtect();
        }
        else
        {
            IntIdtrUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_GDTR)
        {
            IntGdtrProtect();
        }
        else
        {
            IntGdtrUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LOGGER_CONTEXT)
        {
            IntWinInfHookProtect();
        }
        else
        {
            IntWinInfHookUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_NT_EAT_READS)
        {
            IntWinProtectReadNtEat();
        }
        else
        {
            IntWinUnprotectReadNtEat();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS)
        {
            IntWinTokenProtectPrivs();
        }
        else
        {
            IntWinTokenUnprotectPrivs();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SUD_EXEC)
        {
            IntWinSudProtectSudExec();
        }
        else
        {
            IntWinSudUnprotectSudExec();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SUD_INTEGRITY)
        {
            IntWinSudProtectIntegrity();
        }
        else
        {
            IntWinSudUnprotectIntegrity();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_INTERRUPT_OBJ)
        {
            IntWinIntObjProtect();
        }
        else
        {
            IntWinIntObjUnprotect();
        }
    }
    else if (introGuestLinux == gGuest.OSType)
    {
        // Enable or disable detours, depending on active options.
        IntLixApiUpdateHooks();

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LX)
        {
            IntLixKernelWriteProtect();
        }
        else
        {
            IntLixKernelWriteUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LX_TEXT_READS)
        {
            IntLixKernelReadProtect();
        }
        else
        {
            IntLixKernelReadUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_VDSO)
        {
            IntLixVdsoProtect();
        }
        else
        {
            IntLixVdsoUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_MSR_SYSCALL)
        {
            IntMsrSyscallProtect();
        }
        else
        {
            IntMsrSyscallUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CR4)
        {
            IntCr4Protect();
        }
        else
        {
            IntCr4Unprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDT)
        {
            IntLixIdtProtectAll();
        }
        else
        {
            IntLixIdtUnprotectAll();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDTR)
        {
            IntIdtrProtect();
        }
        else
        {
            IntIdtrUnprotect();
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_GDTR)
        {
            IntGdtrProtect();
        }
        else
        {
            IntGdtrUnprotect();
        }

        // INTRO_OPT_PROT_KM_TOKEN_PTR is checked before integrity checks for creds.

        IntLixTaskUpdateProtection();

        IntLixDrvUpdateProtection();
    }
    else
    {
        WARNING("[WARNING] Unknown os type %d.\n", gGuest.OSType);
    }

    IntResumeVcpus();
}


INTSTATUS
IntGuestGetLastGpa(
    _Out_ QWORD *MaxGpa
    )
///
/// @brief      Get the upper limit of the guest physical memory range.
///
/// This value is cached inside the #GUEST_STATE and subsequent calls will return the cached value.
///
/// @param[out] MaxGpa  On success, the upper limit of the guest physical memory range. This is the first page after
///                     the last one that the guest can access, meaning that the available physical address range is
///                     [0, MaxGpa - 1] (inclusive). Note that gaps may be present inside this range.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{

    if (gGuest.Mm.LastGpa == 0)
    {
        QWORD maxGpfn = 0;
        INTSTATUS status = IntGetMaxGpfn(&maxGpfn);

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetMaxGpfn failed: 0x%08x\n", status);
            return status;
        }

        // IntGetMaxGpfn will return the last accessible page frame number, we need to set LastGpa to the next page
        gGuest.Mm.LastGpa = (maxGpfn << 12) + PAGE_SIZE;
    }

    *MaxGpa = gGuest.Mm.LastGpa;
    return INT_STATUS_SUCCESS;
}
