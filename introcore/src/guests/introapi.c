/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introapi.h"
#include "debugger.h"
#include "decoder.h"
#include "deployer.h"
#include "gpacache.h"
#include "guests.h"
#include "kernvm.h"
#include "ptfilter.h"
#include "update_exceptions.h"
#include "vecore.h"

///
/// @file   introapi.c
/// @brief  Contains implementations for the #GLUE_IFACE APIs exposed by Introcore.
///
/// In general, the documentation for these functions is the same as the documentation for the PFUNC_ definitions
/// in glueiface.h. If something is not explicitly documented here, the documentation from glueiface.h is
/// sufficient.
///


static void
IntApiLeave(
    _In_ BOOLEAN Async
    )
///
/// @brief  Handles API exists.
///
/// This should be called before returning from an Introcore API that is exposed to the integrator that are not
/// event callbacks.
///
/// @param[in]  Async   True if the API is not called in the context of a VCPU.
///
{
    INTSTATUS status;

    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | (Async ? 0 : POST_INJECT_PF));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
        IntDbgEnterDebugger();
    }
}


static void
IntApiEnter(
    _In_ DWORD CpuNumber
    )
///
/// @brief  Common API handler.
///
/// This establishes a consistent state for all APIs exposed by Introcore to the integrator that are not event
/// callbacks.
///
/// @param[in]  CpuNumber   The VCPU on which the API was called. If it is not called in the context of a VCPU this
///                         should be set to #IG_CURRENT_VCPU and Introcore will assume that VCPU 0 is used. For
///                         Napoca, since we are always called in the context of a valid VCPU we get the current VCPU.
///
{
    if (CpuNumber == IG_CURRENT_VCPU)
    {
#ifdef USER_MODE
        CpuNumber = 0;
#else
        CpuNumber = IntGetCurrentCpu();
#endif // USER_MODE
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];

    gEventId++;
}


INTSTATUS
IntNewGuestNotification(
    _In_ void *GuestHandle,
    _In_ QWORD Options,
    _In_reads_(BufferLength) PBYTE UpdateBuffer,
    _In_ DWORD BufferLength
    )
///
/// @brief  Handles a new guest. It is essentially the Introcore entry point.
///
/// This is the place in which the process of guest introspection is started. This function loads the CAMI data base
/// and prepares the guest hooking. Even if this function exits with a success status value, it does not mean that
/// the guest is successfully introspected, as certain parts of the initialization are not synchronous. The guest
/// must be considered as not identified until #GLUE_IFACE.NotifyIntrospectionDetectedOs is called, and not protected
/// until #GLUE_IFACE.NotifyIntrospectionActivated is called. Errors can still be encountered while this process takes
/// place, in which case #GLUE_IFACE.NotifyIntrospectionErrorState will be used to report them.
///
/// See #PFUNC_IntNotifyNewGuest for details.
///
/// @param[in]  GuestHandle     Opaque value used to identify the guest. This is used when communicating between the
///                             introspection engine and the integrator and must not change during execution.
/// @param[in]  Options         Protection and activation flags. See @ref group_options
/// @param[in]  UpdateBuffer    The CAMI buffer to be used. If processing this buffer fails, this function will
///                             return one of the #IntCamiSetUpdateBuffer error status values and will set the
///                             error state to #intErrUpdateFileNotSupported. This buffer must remain valid until
///                             Introcore frees it with #GLUE_IFACE.ReleaseBuffer.
/// @param[in]  BufferLength    The size of UpdateBuffer.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if GuestHandle is NULL.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if a guest is already initialized.
///
/// @pre        #IntInit was called and it returned a success status value.
///
{
    INTSTATUS status;

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (gGuest.Initialized)
    {
        WARNING("[WARNING] Introspection is already active, ignoring activation request\n");
        status = INT_STATUS_ALREADY_INITIALIZED_HINT;
        goto release_and_exit;
    }

    gIntHandle = GuestHandle;

    TRACE("[INTRO-INIT] New guest notification, handle = %p\n", gIntHandle);

    LOG("[INTRO-INIT] Will use options: 0x%016llx\n", Options);

    if (Options & INTRO_OPT_ENABLE_KM_BETA_DETECTIONS)
    {
        TRACE("[INTRO-INIT] INTRO_OPT_ENABLE_KM_BETA_DETECTIONS flag set, everything will be allowed in KM.\n");
    }

    gEventId++;

    status = IntCamiSetUpdateBuffer(UpdateBuffer, BufferLength);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCamiSetUpdateBuffer failed: 0x%08x\n", status);

        IntNotifyIntroErrorState(intErrUpdateFileNotSupported, NULL);

        goto release_and_exit;
    }

    status = IntGuestInit(Options);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed initializing guest state: 0x%08x\n", status);
        goto release_and_exit;
    }

release_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntGuestPrepareUninit();

        IntGuestUninit();
    }

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntDisableIntro(
    _In_ void *GuestHandle,
    _In_ QWORD Flags
    )
///
/// @brief  Disables and unloads the introspection engine.
///
/// This is a wrapper over #IntGuestDisableIntro which will ensure that the VCPUs are paused and that #gLock is held.
///
/// See #PFUNC_IntDisableIntro for details.
///
/// @param[in]  GuestHandle Integrator-specific guest identifier.
/// @param[in]  Flags       Flags controlling the disable operation. Can be 0 or #IG_DISABLE_IGNORE_SAFENESS. If
///                         #IG_DISABLE_IGNORE_SAFENESS is used, introcore will forcibly unload even it is not safe to
///                         do that at the moment. This may leave the guest in an unstable state.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_CANNOT_UNLOAD if introcore can not unload.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(GuestHandle);

    IntSpinLockAcquire(gLock);

    IntPauseVcpus();

    if (!gGuest.Initialized)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto resume_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    status = IntGetGprs(IG_CURRENT_VCPU, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

    status = IntGuestDisableIntro(Flags);

resume_and_exit:
    IntResumeVcpus();

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntNotifyGuestPowerStateChange(
    _In_ void *GuestHandle,
    _In_ IG_GUEST_POWER_STATE PowerState
    )
///
/// @brief      Handles guest power state transitions.
///
/// If the guest is transitioning to the #intGuestPowerStateSleep power state, #gLock will be acquired, which will
/// ensure that all events will be blocked until the guest resumes from sleep (#intGuestPowerStateResume). This
/// assumes that the resume event is always sent after the sleep event and that no consecutive sleep events are sent.
///
/// See #PFUNC_IntNotifyGuestPowerStateChange for details.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier. Ignored.
/// @param[in]  PowerState      The power state to which the guest is transitioning.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    UNREFERENCED_PARAMETER(GuestHandle);

    switch (PowerState)
    {
    case intGuestPowerStateSleep:
    {
        IntSpinLockAcquire(gLock);
        return INT_STATUS_SUCCESS;
    }

    case intGuestPowerStateResume:
    {
        // We already disabled pt filtering on sleep on NtSetSystemPowerState callback
        IntPtiHandleGuestResumeFromSleep();

        // We already disabled #VE on sleep on NtSetSystemPowerState callback
        IntVeHandleGuestResumeFromSleep();

        IntSpinLockRelease(gLock);
        return INT_STATUS_SUCCESS;
    }

    case intGuestPowerStateShutDown:
    {
        IntSpinLockAcquire(gLock);

        gGuest.ShutDown = TRUE;

        IntSpinLockRelease(gLock);
        return INT_STATUS_SUCCESS;
    }

    case intGuestPowerStateTerminating:

        IntSpinLockAcquire(gLock);

        gGuest.Terminating = TRUE;

        IntSpinLockRelease(gLock);
        return INT_STATUS_SUCCESS;

    default:
        ERROR("[ERROR] Invalid power state: %d\n", PowerState);
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntAddRemoveProtectedProcessUtf8(
    _In_ void *GuestHandle,
    _In_z_ const CHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    )
///
/// @brief  Toggles protection options for a process.
///
/// See #PFUNC_IntAddRemoveProtectedProcessUtf8 for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;
    size_t len, i;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == FullPath)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.UninitPrepared)
    {
        WARNING("[WARNING] The uninit has been called, cannot modify the protected process list!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto release_and_exit;
    }

    IntPauseVcpus();

    if (gGuest.OSType == introGuestWindows)
    {
        PWCHAR wPath = NULL;

        len = strlen(FullPath);

        if (len >= 0x10000)
        {
            status = INT_STATUS_INVALID_PARAMETER_2;
            goto resume_and_exit;
        }

        // len + 1 OK: len is not longer than 64K.
        wPath = HpAllocWithTag((len + 1) * 2, IC_TAG_ALLOC);
        if (NULL == wPath)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto resume_and_exit;
        }

        // Copy from CHAR to WCHAR - no explicit conversion.
        for (i = 0; i < len; i++)
        {
            wPath[i] = (WCHAR)FullPath[i];
        }

        wPath[i] = 0;

        if (Add)
        {
            status = IntWinProcAddProtectedProcess(wPath, ProtectionMask, Context);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcAddProtectedProcess failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntWinProcRemoveProtectedProcess(wPath);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcRemoveProtectedProcess failed: 0x%08x\n", status);
            }
        }

        HpFreeAndNullWithTag(&wPath, IC_TAG_ALLOC);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        if (Add)
        {
            status = IntLixTaskAddProtected(FullPath, ProtectionMask, Context);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixTaskAddProtected failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntLixTaskRemoveProtected(FullPath);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixTaskRemoveProtected failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

resume_and_exit:
    IntResumeVcpus();

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntAddRemoveProtectedProcessUtf16(
    _In_ void *GuestHandle,
    _In_z_ const WCHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    )
///
/// @brief  Toggles protection options for a process.
///
/// See #PFUNC_IntAddRemoveProtectedProcessUtf16 for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == FullPath)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.UninitPrepared)
    {
        ERROR("[ERROR] The uninit has been called, cannot modify the protected process list!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto release_and_exit;
    }

    IntPauseVcpus();

    if (introGuestWindows == gGuest.OSType)
    {
        if (Add)
        {
            status = IntWinProcAddProtectedProcess(FullPath, ProtectionMask, Context);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcAddProtectedProcess failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntWinProcRemoveProtectedProcess(FullPath);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcRemoveProtectedProcess failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    IntResumeVcpus();

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntRemoveAllProtectedProcesses(
    _In_ void *GuestHandle
    )
///
/// @brief  Removes the protection policies for all processes.
///
/// See #PFUNC_IntRemoveAllProtectedProcesses for details.
///
/// @retval #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.UninitPrepared)
    {
        ERROR("[ERROR] The uninit has been called, cannot modify the protected process list!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto release_and_exit;
    }

    if (introGuestWindows == gGuest.OSType)
    {
        status = IntWinProcRemoveAllProtectedProcesses();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcRemoveAllProtectedProcesses failed: 0x%08x\n", status);
        }
    }
    else
    {
        status = INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntInjectProcessAgentInGuest(
    _In_ void *GuestHandle,
    _In_ DWORD AgentTag,
    _In_opt_ PBYTE AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_z_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    )
///
/// @brief  Requests a process agent injection inside the guest.
///
/// See #PFUNC_IntInjectProcessAgent for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(GuestHandle);

    IntSpinLockAcquire(gLock);

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    if (gGuest.BugCheckInProgress)
    {
        ERROR("[ERROR] Agent injection called when guest has bugcheck in progress!\n");
        status = INT_STATUS_UNINIT_BUGCHECK;
        goto release_and_exit;
    }

    if (!gGuest.GuestInitialized)
    {
        WARNING("[WARNING] Agent %s will not be deployed as the guest is NOT initialized!\n", Name);
        status = INT_STATUS_NOT_INITIALIZED;
        goto cleanup_and_exit;
    }

    if (gGuest.UninitPrepared)
    {
        WARNING("[WARNING] The uninit has been called, cannot inject agents anymore!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto cleanup_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.CoreOptions.Current & INTRO_OPT_AGENT_INJECTION)
    {
        status = IntDepInjectProcess(AgentTag, AgentContent, AgentSize, Name, Args);
    }
    else
    {
        WARNING("[WARNING] Requested to inject agents but INTRO_OPT_AGENT_INJECTION is not set!\n");

        status = INT_STATUS_NOT_SUPPORTED;
    }

cleanup_and_exit:
    IntApiLeave(TRUE);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntInjectFileAgentInGuest(
    _In_ void *GuestHandle,
    _In_ PBYTE AgentContent,
    _In_ DWORD AgentSize,
    _In_z_ const CHAR *Name
    )
///
/// @brief  Drops a file on the guest hard disk.
///
/// See #PFUNC_IntInjectFileAgent for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(GuestHandle);

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    if (gGuest.BugCheckInProgress)
    {
        ERROR("[ERROR] Agent injection called when guest has bugcheck in progress!\n");
        status = INT_STATUS_UNINIT_BUGCHECK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.UninitPrepared)
    {
        ERROR("[ERROR] The uninit has been called, cannot inject agents anymore!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto cleanup_and_exit;
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_AGENT_INJECTION)
    {
        status = IntDepInjectFile(AgentContent, AgentSize, Name);
    }
    else
    {
        WARNING("[WARNING] Requested to inject a file but INTRO_OPT_AGENT_INJECTION is not set!\n");

        status = INT_STATUS_NOT_SUPPORTED;
    }

cleanup_and_exit:
    IntApiLeave(TRUE);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntGetCurrentInstructionLength(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ BYTE *Length
    )
///
/// @brief  Returns the length of the instruction at which the current guest RIP points.
///
/// See #PFUNC_IntGetCurrentInstructionLength for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;
    INSTRUX instrux;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    gVcpu = &gGuest.VcpuArray[CpuNumber];

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntDecDecodeInstructionAtRipWithCache(gGuest.InstructionCache, CpuNumber,
                                                   &gVcpu->Regs, &instrux, DEC_OPT_NO_CACHE, NULL, NULL);
    if (!INT_SUCCESS(status) && ((INT_STATUS_PAGE_NOT_PRESENT != status) &&
                                 (INT_STATUS_NO_MAPPING_STRUCTURES != status)))
    {
        ERROR("[ERROR] IntDecDecodeInstructionAtRipWithCache failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (INT_SUCCESS(status))
    {
        *Length = instrux.Length;
    }

cleanup_and_exit:
    IntApiLeave(TRUE);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntGetCurrentInstructionMnemonic(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ CHAR *Mnemonic
    )
///
/// @brief  Returns the mnemonic of the instruction at which the current guest RIP points.
///
/// See #PFUNC_IntGetCurrentInstructionMnemonic for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;
    INSTRUX instrux;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Mnemonic)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(CpuNumber);

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntDecDecodeInstructionAtRipWithCache(gGuest.InstructionCache, CpuNumber,
                                                   &gVcpu->Regs, &instrux, DEC_OPT_NO_CACHE, NULL, NULL);
    if (!INT_SUCCESS(status) && ((INT_STATUS_PAGE_NOT_PRESENT != status) &&
                                 (INT_STATUS_NO_MAPPING_STRUCTURES != status)))
    {
        ERROR("[ERROR] IntDecDecodeInstructionAtRipWithCache failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (INT_SUCCESS(status))
    {
        strlcpy(Mnemonic, instrux.Mnemonic, ND_MAX_MNEMONIC_LENGTH);
    }

cleanup_and_exit:
    IntApiLeave(TRUE);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntIterateVaSpace(
    _In_ void *GuestHandle,
    _In_ QWORD Cr3,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    )
///
/// @brief  Iterates over the guest virtual address space.
///
/// See #PFUNC_IntIterateVaSpace for details.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    IntSpinLockAcquire(gLock);

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    status = IntIterateVirtualAddressSpace(Cr3, Callback);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIterateVirtualAddressSpace failed: 0x%x\n", status);
    }

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntGetGuestInfo(
    _In_ void *GuestHandle,
    _Out_ GUEST_INFO *GuestInfo
    )
///
/// @brief  Get a description of the introspected guest.
///
/// See #PFUNC_IntGetGuestInfo for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == GuestInfo)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    status = IntGuestGetInfo(GuestInfo);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntModifyDynamicOptions(
    _In_ void *GuestHandle,
    _In_ QWORD NewOptions
    )
///
/// @brief  Modifies the introcore options.
///
/// See #PFUNC_IntModifyDynamicOptions for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    IntGuestUpdateCoreOptions(NewOptions);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntFlushGpaCache(
    _In_ void *GuestHandle
    )
///
/// @brief  Flushed the introcore GPA cache.
///
/// See #PFUNC_IntFlushGpaCache for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    if (NULL == gGuest.GpaCache)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    status = IntGpaCacheFlush(gGuest.GpaCache);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntGetCurrentIntroOptions(
    _In_  void *GuestHandle,
    _Out_ QWORD *IntroOptions
    )
///
/// @brief  Get the currently used introcore options.
///
/// See #PFUNC_IntGetCurrentIntroOptions for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == IntroOptions)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    *IntroOptions = gGuest.CoreOptions.Current;

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntUpdateSupport(
    _In_ void *GuestHandle,
    _In_reads_bytes_(Length) PBYTE Buffer,
    _In_ DWORD Length
    )
///
/// @brief      Loads a new CAMI version.
///
/// See #PFUNC_IntUpdateSupport for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
/// @remarks    After a successful call, the previously loaded CAMI settings are removed.
///
{
    INTSTATUS status;
    DWORD osType = 0;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized || !gGuest.SafeToApplyOptions)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    if (gGuest.UninitPrepared)
    {
        ERROR("[ERROR] The uninit has been called, won't load the update buffer!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto release_and_exit;
    }

    IntApiEnter(IG_CURRENT_VCPU);

    // Notify the integrator that we no longer need the previous cami buffer
    IntCamiClearUpdateBuffer();

    status = IntCamiSetUpdateBuffer(Buffer, Length);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCamiSetUpdateBuffer failed: %08x\n", status);
        goto release_and_exit;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        osType = CAMI_SECTION_HINT_WINDOWS;
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        osType = CAMI_SECTION_HINT_LINUX;
    }

    if (osType != 0)
    {
        status = IntCamiLoadSection(CAMI_SECTION_HINT_PROT_OPTIONS | osType);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiLoadSection failed: %08x\n", status);
            goto release_and_exit;
        }
    }

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntGetSupportVersion(
    _In_ void *GuestHandle,
    _Out_ DWORD *MajorVersion,
    _Out_ DWORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    )
///
/// @brief  Get the current version of CAMI.
///
/// See #PFUNC_IntGetSupportVersion for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    status = IntCamiGetVersion(MajorVersion, MinorVersion, BuildNumber);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntProcessDebugCommand(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ DWORD Argc,
    _In_ CHAR *Argv[]
    )
///
/// @brief  Executes a debugger command.
///
/// This function does not acquire #gLock like all the other #GLUE_IFACE APIs since a lot of the time, while
/// debugging, we may already hold the lock, which will cause a dead lock. Since this offers only debugging
/// functionalities this is not a problem.
///
/// See #PFUNC_IntDebugProcessCommand.
///
/// @param[in]  GuestHandle     Integrator-specific guest identifier.
/// @param[in]  CpuNumber       The current VCPU number.
/// @param[in]  Argc            The number of arguments.
/// @param[in]  Argv            An array of NULL terminated strings.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    void *oldVcpu;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    oldVcpu = gVcpu;

    IntApiEnter(CpuNumber);

    IntDbgProcessCommand(Argc, Argv);

    gVcpu = oldVcpu;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGetExceptionsVersion(
    _In_ void *GuestHandle,
    _Out_ WORD *MajorVersion,
    _Out_ WORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    )
///
/// @brief      Get the current exceptions version.
/// @ingroup    group_exceptions
///
/// See #PFUNC_IntGetExceptionsVersion for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    status = IntUpdateGetVersion(MajorVersion, MinorVersion, BuildNumber);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntUpdateExceptions(
    _In_ void *GuestHandle,
    _In_reads_bytes_(Length) PBYTE Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
    )
///
/// @brief      Loads a new exceptions version.
/// @ingroup    group_exceptions
///
/// See #PFUNC_IntUpdateExceptions for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // We must take this spinlock exclusive, so we don't process any event.
    // This way, we won't miss any events (there will be a small attack-window)
    // while we free the exceptions and load the new ones.
    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    status = IntUpdateLoadExceptions(Buffer, Length, Flags);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntAddExceptionFromAlert(
    _In_ void *GuestHandle,
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
    )
///
/// @brief      Adds an exception for an alert reported by introcore.
/// @ingroup    group_exceptions
///
/// See #PFUNC_IntAddExceptionFromAlert for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    status = IntUpdateAddExceptionFromAlert(Event, Type, Exception, Context);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntRemoveException(
    _In_ void *GuestHandle,
    _In_opt_ QWORD Context
    )
///
/// @brief      Removes a custom exception added with #GLUE_IFACE.AddExceptionFromAlert.
/// @ingroup    group_exceptions
///
/// See #PFUNC_IntRemoveException for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    status = IntUpdateRemoveException(Context);

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntFlushAlertExceptions(
    _In_ void *GuestHandle
    )
///
/// @brief      Removes all the custom exceptions added with #GLUE_IFACE.AddExceptionFromAlert.
/// @ingroup    group_exceptions
///
/// See #PFUNC_IntFlushAlertExceptions for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.Initialized)
    {
        ERROR("[ERROR] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    status = IntUpdateFlushAlertExceptions();

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntAbortEnableIntro(
    _In_ void *GuestHandle,
    _In_ BOOLEAN Abort
    )
///
/// @brief  Abort the introcore loading process.
///
/// See #PFUNC_IntSetIntroAbortStatus for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    UNREFERENCED_PARAMETER(GuestHandle);

    if (gGuest.EnterHibernate)
    {
        return INT_STATUS_POWER_STATE_BLOCK;
    }

    gAbortLoad = Abort;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSetLogLevel(
    _In_ void *GuestHandle,
    _In_ IG_LOG_LEVEL LogLevel
    )
///
/// @brief  Sets the log level.
///
/// See #PFUNC_IntSetLogLevel for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    gLogLevel = LogLevel;

    IntSpinLockRelease(gLock);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGetVersionString(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    )
///
/// @brief  Get the version string information for the current guest.
///
/// See #PFUNC_IntGetVersionString for details.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == FullString)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == VersionString)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    IntSpinLockAcquire(gLock);

    if (!gGuest.GuestInitialized)
    {
        WARNING("[WARNING] Introspection is not initialized!\n");
        status = INT_STATUS_NOT_INITIALIZED;
        goto release_and_exit;
    }

    if (gGuest.EnterHibernate)
    {
        status = INT_STATUS_POWER_STATE_BLOCK;
        goto release_and_exit;
    }

    gEventId++;

    IntApiEnter(IG_CURRENT_VCPU);

    if (gGuest.UninitPrepared)
    {
        WARNING("[WARNING] The uninit has been called, cannot send version strings!\n");
        status = INT_STATUS_NOT_SUPPORTED;
        goto release_and_exit;
    }

    if (introGuestLinux == gGuest.OSType)
    {
        status = IntGetVersionStringLinux(FullStringSize, VersionStringSize, FullString, VersionString);
        if (!INT_SUCCESS(status))
        {
            LOG("[ERROR] Could not get Linux version string: 0x%08x\n", status);
        }
    }
    else if (introGuestWindows == gGuest.OSType)
    {
        status = IntWinGetVersionString(FullStringSize, VersionStringSize, FullString, VersionString);
        if (!INT_SUCCESS(status))
        {
            LOG("[ERROR] Could not get Windows version string: 0x%08x\n", status);
        }
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

release_and_exit:
    IntSpinLockRelease(gLock);

    return status;
}
