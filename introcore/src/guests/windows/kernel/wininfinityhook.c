/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wininfinityhook.h"
#include "decoder.h"
#include "hook.h"
#include "winpe.h"
#include "alerts.h"


///
/// @file: wininfinityhook.c
///
/// @brief  This file confers protection against the infinity hook technique.
///
/// The infinity hook technique consists in modifying the GetCpuClock field of the WMI_LOGGER_CONTEXT
/// structure. By hooking this function pointer, one can then activate the Etw tracing mechanism on
/// syscalls, meaning that, on every syscall, the GetCpuClock function will get called. In this manner,
/// one can detour all the system calls, which can therefore be used for a variety of malicious purposes.
/// In order to perform this technique, one must first search for the WMI_LOGGER_CONTEXT structure. One
/// must start with the EtwpDebuggerData structure, which may be found through search for a specific
/// hard coded pattern, namely "0x2c 0x08 0x04 0x38 0x0c", which is a signature at offset 2 inside this
/// structure. After this, one should get the EtwpDebuggerDataSilo field, where the third pointer represents
/// the WMI_LOGGER_CONTEXT structure for the Circular Kernel Context Logger used in Etw tracing.
/// In order to protect this field, the introspection engine can either verify the GetCpuClock through
/// the integrity mechanism, once every second, either hook the structure through EPT in order to trigger
/// violations right when the pointer is modified. The last options would obviously cause a high performance
/// impact, since the WMI_LOGGER_CONTEXT structure is a data structure, thus we will hook it through EPT
/// only if the SPP support is present, minimizing the number of irrelevant writes.
///


///
/// The WMI_LOGGER_CONTEXT pointer is always aligned to 0x10. The lower bits are used sometimes
/// for other things and are not taken into consideration. For now it seems that only the first
/// bit is set to signal that the logger should be closed. If it is set the kernel will call
/// nt!EtwpCloseLogger at the very first nt!EtwpLogKernelEvent that is called. This mask is used
/// in order to clear this bit for proper access to the WMI_LOGGER_CONTEXT structure.
///
#define WMI_PTR_MASK         0xFFFFFFFFFFFFFFFE


//#define OPT_SET_WMI_SPP_STATS

///
/// Object containing the current state of the protected WMI_LOGGER_CONTEXT structure.
///
typedef struct _WIN_LOGGER_CTX_STATE
{
    QWORD WmiLoggerCtx;                 ///< Keeps the current address of WMI_LOGGER_CTX.
    /// Keeps the address of the pointer to WMI_LOGGER_CONTEXT (basically EtwDebuggerDataSilo + 0x10).
    QWORD LoggerGvaInSilo;
    /// Keeps the current, known WMI_LOGGER_CONTEXT.GetCpuClock which is verified on integrity.
    QWORD CurrentGetCpuClock;

    QWORD EtwDbgDataGva;                ///< The guest virtual address of EtwpDebuggerData.

    BOOLEAN Initialized;                ///< Set if the protection is initialized.
    /// Set if the protection failed to initialize, in order to avoid retrying indefinitely.
    BOOLEAN FailedToInitialize;

    void *WmiLoggerIntegrityObject; ///< Integrity object for WMI_LOGGER_CONTEXT.GetCpuClock.
    void *SiloIntegrityObject;      ///< Integrity object for EtwDebuggerDataSilo.WmiCtxLoggerPtr.

    void *WmiLoggerHookObject;      ///< Hook object for SPP hooking of WMI_LOGGER_CONTEXT.GetCpuClock.
    void *WmiLoggerHookObjectStats; ///< Hook object for SPP statistics on WMI_LOGGER_CONTEXT.GetCpuClock.

    /// Hook object for SPP hooking on EtwDebuggerDataSilo - needed for when WMI_LOGGER_CONTEXT is relocated.
    void *SiloHookObject;
    void *SiloHookObjectStats;      ///< Hook object for SPP statistics on EtwDebuggerDataSilo.

    /// Hook object for the first write of the GVA of EtwpDbgDataSilo inside EtwpDbgData.
    ///
    /// Needed in case it is not initialized yet.
    void *FirstSiloWriteHookObject;

    QWORD SiloTotal;                ///< SPP stats for EtwDebuggerDataSilo, containing the number of total writes.
    /// SPP stats for EtwDebuggerDataSilo, containing the number of writes that we are interested into.
    QWORD SiloInteresting;

    QWORD WmiTotal;                 ///< SPP stats for WMI_LOGGER_CONTEXT, containing the number of total writes.
    /// SPP stats for WMI_LOGGER_CONTEXT, containing the number of writes that we are interested into.
    QWORD WmiInteresting;

} WIN_LOGGER_CTX_STATE, *PWIN_LOGGER_CTX_STATE;


///
/// Global structure containing the state of the WMI_LOGGER_CONTEXT structure protection.
///
WIN_LOGGER_CTX_STATE gLoggerCtxState = { 0 };


static INTSTATUS
IntWinInfHookIntegrityHandleWrite(
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _In_opt_ INTEGRITY_REGION *IntegrityRegion,
    _Inout_ INTRO_ACTION *Action
    );


static INTSTATUS
IntWinInfCheckCtxLoggerOnRelocation(
    void
    )
///
/// @brief  Checks the WMI_LOGGER_CONTEXT when the pointer to the old structure has changed in the
///         EtwDebuggerDataSilo structure.
///
/// As seen on various Windows versions, the WMI_LOGGER_CONTEXT structure tends to relocate in some
/// cases. When a relocation occurs, we must check if the new pointer contains a GetCpuClock which
/// can lead to malicious actions on the system. For this reason, if the GetCpuClock pointer is not
/// inside the kernel or is not equal to the old known one we will handle the modification in the
/// same manner in which a modification would be detected through the integrity mechanism, by calling
/// #IntWinInfHookIntegrityHandleWrite. If there is no known old pointer, we will also go through
/// the exception mechanism to check the new pointer, and send an alert if necessary.
///
/// @retval     #INT_STATUS_SUCCESS On success
/// @retval     #INT_STATUS_NOT_INITIALIZED If the current pointer is 0 or if the first bit in the pointer
///                                         is set. See #WMI_PTR_MASK for more details.
///
{
    INTSTATUS status;
    QWORD currentCpuGetClock = 0;
    KERNEL_DRIVER *pDrv = NULL;
    INTRO_ACTION action = introGuestAllowed;

    if ((gLoggerCtxState.WmiLoggerCtx & 1) || (gLoggerCtxState.WmiLoggerCtx & WMI_PTR_MASK) == 0)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    status = IntKernVirtMemRead(gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                gGuest.WordSize,
                                &currentCpuGetClock,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    pDrv = IntDriverFindByAddress(currentCpuGetClock);
    if (NULL != pDrv && pDrv->BaseVa == gGuest.KernelVa)
    {
        // If the new GetCpuClock resides in the kernel, always consider it.
        gLoggerCtxState.CurrentGetCpuClock = currentCpuGetClock;

        return INT_STATUS_SUCCESS;
    }

    if (gLoggerCtxState.CurrentGetCpuClock == 0)
    {
        // We have a relocation on which we don't previously have any known good GetCpuClock value
        // and the new value doesn't reside in kernel. At least send an alert for this case.
        status = IntWinInfHookIntegrityHandleWrite(gLoggerCtxState.CurrentGetCpuClock, currentCpuGetClock, NULL,
                                                   &action);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinInfHookIntegrityHandleWrite failed: 0x%08x\n", status);
            return status;
        }

        // If we allowed the "relocation" to take place with a non-kernel resident GetCpuClock, then
        // we must consider the current GetCpuClock as the real one and protect it.
        if (action == introGuestAllowed)
        {
            gLoggerCtxState.CurrentGetCpuClock = currentCpuGetClock;
            return INT_STATUS_SUCCESS;
        }

        return INT_STATUS_NOT_INITIALIZED;
    }

    if (currentCpuGetClock == gLoggerCtxState.CurrentGetCpuClock)
    {
        return INT_STATUS_SUCCESS;
    }

    // If allowed, we must not write the old GetCpuClock, but rather
    // we should consider the current cpugetclock to be the "old one" for further writes

    status = IntWinInfHookIntegrityHandleWrite(gLoggerCtxState.CurrentGetCpuClock, currentCpuGetClock, NULL, &action);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookIntegrityHandleWrite failed: 0x%08x\n", status);
        return status;
    }

    if (introGuestAllowed == action)
    {
        gLoggerCtxState.CurrentGetCpuClock = currentCpuGetClock;
    }
    else if (introGuestNotAllowed == action)
    {
        IntPauseVcpus();

        status = IntKernVirtMemWrite(gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                     gGuest.WordSize,
                                     &gLoggerCtxState.CurrentGetCpuClock);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    // Since we have the old CpuGetClock and we overwritten it, we should protect the new WMI_LOGGER_CONTEXT.
    return status;
}


static INTSTATUS
IntWinInfHookEptSppSendAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an alert for an EPT violation. Used only when SPP mechanism is supported.
///
/// When a write occurs on the GetCpuClock an EPT violation will occur when the SPP mechanism
/// is supported (due to performance reasons). If, after checking the exceptions, the write
/// is considered malicious, an alert will be sent through this function.
///
/// @param[in]  Victim      The #EXCEPTION_VICTIM_ZONE describing the victim, in this case the
///                         Circular Kernel Context Logger.
/// @param[in]  Originator  The #EXCEPTION_KM_ORIGINATOR describing the originator who made
///                         the write, in this case a kernel driver.
/// @param[in]  Action      The action taken by the exception mechanism.
/// @param[in]  Reason      The reason why the exception mechanism took the given action.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PEVENT_EPT_VIOLATION pEptViol;
    PIG_ARCH_REGS regs;

    regs = &gVcpu->Regs;

    pEptViol = &gAlert.Ept;
    memzero(pEptViol, sizeof(*pEptViol));

    pEptViol->Header.Action = Action;
    pEptViol->Header.Reason = Reason;
    pEptViol->Header.MitreID = idRootkit;

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(Originator, pEptViol);
    IntAlertEptFillFromVictimZone(Victim, pEptViol);

    pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Reason);

    IntAlertFillWinProcessByCr3(regs->Cr3, &pEptViol->Header.CurrentProcess);

    IntAlertFillCodeBlocks(Originator->Original.Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
    IntAlertFillExecContext(0, &pEptViol->ExecContext);

    IntAlertFillVersionInfo(&pEptViol->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinInfHookEptSppHandleWrite(
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief  Handles a write detected through EPT over WMI_LOGGER_CONTEXT's GetCpuClock function pointer
///         and takes an action based on the exceptions, sending an alert if necessary.
///
/// @param[in, out] Action  A pointer to the #INTRO_ACTION which is being taken by the exception
///                         mechanism.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    INTRO_ACTION_REASON reason;
    INTSTATUS status;
    BOOLEAN exitAfterInformation = FALSE;

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

    status = IntExceptGetVictimEpt(NULL,
                                   0,
                                   gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                   introObjectTypeKmLoggerContext,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventIntegrityViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Action, &reason))
    {
        IntWinInfHookEptSppSendAlert(&victim, &originator, *Action, reason);

        LOG("[INFINITY-HOOK] Detected modification of WMI_LOGGER_CONTEXT.GetCpuClock. Rip: 0x%016llx\n",
            gVcpu->Regs.Rip);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Action);

    return status;
}


static INTSTATUS
IntWinInfHookWmiGetCpuClockSppCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief  EPT callback for writes over WMI_LOGGER_CONTEXT's GetCpuClock.
///
/// This function serves as a wrapper for #IntWinInfHookEptSppHandleWrite, also increasing the number
/// of interesting writes for the purpose of measuring the improvements which SPP mechanism brings.
///
/// @param[in]  Context         The user provided context set when the hook was established.
/// @param[in]  Hook            The EPT hook object for which the callback was called.
/// @param[in]  Address         The address on which the EPT violation occurred.
/// @param[in, out]  Action     A pointer to an #INTRO_ACTION, which is to be completed based
///                             on the exception mechanism decision.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    gLoggerCtxState.WmiInteresting++;

    TRACE("[SPP WMI STATS] Total writes: 0x%016llx, interesting: 0x%016llx\n",
          gLoggerCtxState.WmiTotal, gLoggerCtxState.WmiInteresting);

    status = IntWinInfHookEptSppHandleWrite(Action);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookEptSppHandleWrite failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookWmiGetCpuClockSppStatsCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  EPT callback for the SPP region on which exits will always occur on the GetCpuClock
///         EPT hook.
///
/// This function will be called when any write in the range [WMI_LOGGER_CONTEXT & 0x80,
/// WMI_LOGGER_CONTEXT & 0x80 + 0x80] is made, in order to measure the total number of writes
/// in the SPP region. Used only for statistics, when OPT_SET_WMI_SPP_STATS is defined.
///
/// @param[in]  Context         The user provided context set when the hook was established.
/// @param[in]  Hook            The EPT hook object for which the callback was called.
/// @param[in]  Address         The address on which the EPT violation occurred.
/// @param[in, out]  Action     A pointer to an #INTRO_ACTION, which will always be set to
///                             introGuestAllowed as this callback is used only for statistics.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    gLoggerCtxState.WmiTotal++;

    if (gLoggerCtxState.WmiTotal % 1000 == 0)
    {
        LOG("[SPP WMI STATS] Total writes: 0x%016llx, interesting: 0x%016llx\n", gLoggerCtxState.WmiTotal,
            gLoggerCtxState.WmiInteresting);
    }

    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookHookSppWmiGetClock(
    void
    )
///
/// @brief  Establishes the EPT hook on the WMI_LOGGER_CONTEXT's GetCpuClock field.
///
/// If OPT_SET_WMI_SPP_STATS is defined it will also set an EPT hook in order to measure the total number of writes in
/// the SPP region in which the GetCpuClock field resides.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED If the hook is already established.
///
{
    INTSTATUS status = INT_STATUS_ALREADY_INITIALIZED;

    LOG("[INFO] Request to hook logger CTX 0x%016llx through SPP\n", gLoggerCtxState.WmiLoggerCtx);

    if (NULL == gLoggerCtxState.WmiLoggerHookObject)
    {
        status = IntHookObjectCreate(introObjectTypeKmLoggerContext,
                                     gGuest.Mm.SystemCr3,
                                     &gLoggerCtxState.WmiLoggerHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookObjectHookRegion(gLoggerCtxState.WmiLoggerHookObject,
                                         gGuest.Mm.SystemCr3,
                                         gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                         gGuest.WordSize,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinInfHookWmiGetCpuClockSppCallback,
                                         NULL,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            return status;
        }

        LOG("[INFO] Successfully hooked logger CTX 0x%016llx\n", gLoggerCtxState.WmiLoggerCtx);
    }

#ifdef OPT_SET_WMI_SPP_STATS
    if (NULL == gLoggerCtxState.WmiLoggerHookObjectStats)
    {
        status = IntHookObjectCreate(introObjectTypeKmLoggerContext, gGuest.Mm.SystemCr3,
                                     &gLoggerCtxState.WmiLoggerHookObjectStats);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookObjectHookRegion(gLoggerCtxState.WmiLoggerHookObjectStats,
                                         gGuest.Mm.SystemCr3,
                                         gLoggerCtxState.WmiLoggerCtx & 0xFFFFFFFFFFFFFF80,
                                         0x80,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinInfHookWmiGetCpuClockSppStatsCallback,
                                         NULL,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            return status;
        }
    }
#endif

    return status;
}


static INTSTATUS
IntWinInfHookSppViolationCallbackWmiPtrChanged(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  EPT callback for writes over the WMI_LOGGER_CONTEXT pointer inside the EtwDebuggerDataSilo structure.
///
/// When a write occurs over the WMI_LOGGER_CONTEXT pointer, this function will be called. It is needed to intercept
/// writes over this pointer in order to find when the WMI_LOGGER_CONTEXT is relocated, so that the EPT hook on
/// GetCpuClock can be adjusted if needed. Also, it is a measure of protection in case of malicious relocations.
/// For example, a malicious driver can change the pointer to a structure having the GetCpuClock function pointer
/// already hooked. For this reasons, checks are made in order to determine whether the relocation is a malicious or
/// not, and an alert will be sent if, after consulting the exception mechanism, it is decided that it is malicious.
///
/// @param[in]  Context         The user provided context set when the hook was established.
/// @param[in]  Hook            The EPT hook object for which the callback was called.
/// @param[in]  Address         The address on which the EPT violation occurred.
/// @param[in, out]  Action     A pointer to an #INTRO_ACTION, which will always be set to #introGuestAllowed, as the
///                             relocation must occur, but the GetCpuClock will be overwritten with the original value
///                             if the relocation is considered malicious.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    OPERAND_VALUE writtenValue = { 0 };
    INTSTATUS status;
    QWORD newValue;
    KERNEL_DRIVER *pDrv = NULL;
    BOOLEAN shouldSkipHook = FALSE;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    gLoggerCtxState.SiloInteresting++;

    LOG("[SPP SILO WMI] Ptr changed, total: 0x%016llx, interesting: 0x%016llx\n", gLoggerCtxState.SiloTotal,
        gLoggerCtxState.SiloInteresting);

    status = IntDecGetWrittenValueFromInstruction(&gVcpu->Instruction, &gVcpu->Regs, NULL, &writtenValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecGetWrittenValueFromInstruction failed: 0x%08x\n", status);
        return status;
    }

    newValue = writtenValue.Value.QwordValues[0] & WMI_PTR_MASK;

    // If the first bit is set, then at the very first call of EtwpLogKernelEvent, the kernel will call
    // nt!EtwpCloseLogger on the WMI_LOGGER_CONTEXT, as it means that it is no longer a valid context and is waiting
    // to be closed.
    shouldSkipHook = (writtenValue.Value.QwordValues[0] & 1) || newValue == 0;

    LOG("[INFO] WMI_LOGGER_CONTEXT relocated from 0x%016llx to 0x%016llx (ptr 0x%016llx)\n",
        gLoggerCtxState.WmiLoggerCtx, newValue, writtenValue.Value.QwordValues[0]);

    if (NULL != gLoggerCtxState.WmiLoggerHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.WmiLoggerHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != gLoggerCtxState.WmiLoggerHookObjectStats)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.WmiLoggerHookObjectStats, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    gLoggerCtxState.WmiLoggerCtx = newValue;

    if (shouldSkipHook)
    {
        goto _allow_and_exit;
    }

    // First verify here if the new WMI_LOGGER_CONTEXT.GetCpuClock resides in kernel. If it doesn't, we will send an
    // integrity alert and don't add the new integrity region. If we know the real WMI_LOGGER_CONTEXT.GetCpuClock from
    // the kernel we will overwrite it and then protect the new region. But if something fails, we shouldn't protect the
    // relocated structure.
    // Only check relocation if rip is not inside kernel. From empiric evidence, the kernel can use the
    // EtwDbgDataSilo + 0x10 for other things inside the ETW mechanism for short periods of time. So, don't bother
    // checking those if the rip is in kernel.
    pDrv = IntDriverFindByAddress(gVcpu->Regs.Rip);
    if (NULL == pDrv || pDrv->BaseVa != gGuest.KernelVa)
    {
        status = IntWinInfCheckCtxLoggerOnRelocation();
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinInfCheckCtxLoggerOnRelocation failed: 0x%08x\n", status);
            goto _allow_and_exit;
        }
    }
    else
    {
        LOG("[INFO] WMI_LOGGER_CONTEXT relocated from kernel, RIP 0x%016llx, we'll trust it\n", gVcpu->Regs.Rip);
    }

    status = IntWinInfHookHookSppWmiGetClock();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookHookSppWmiGetClock failed: 0x%08x\n", status);
    }

_allow_and_exit:
    *Action = introGuestAllowed;

    return status;
}


static INTSTATUS
IntWinInfHookSppWmiSiloStatsCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  EPT callback for the SPP region on which exits will always occur on the EtwpDebuggerDataSilo
///         EPT hook.
///
/// This function will be called when any write in the range [EtwpDebuggerDataSilo & 0x80,
/// EtwpDebuggerDataSilo & 0x80 + 0x80] is made, in order to measure the total number of writes
/// in the SPP region. Used only for statistics, when OPT_SET_WMI_SPP_STATS is defined.
///
/// @param[in]  Context         The user provided context set when the hook was established.
/// @param[in]  Hook            The EPT hook object for which the callback was called.
/// @param[in]  Address         The address on which the EPT violation occurred.
/// @param[in, out]  Action     A pointer to an #INTRO_ACTION, which will always be set to
///                             introGuestAllowed as this callback is used only for statistics.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    *Action = introGuestAllowed;

    gLoggerCtxState.SiloTotal++;

    if (gLoggerCtxState.SiloTotal % 1000 == 0)
    {
        LOG("[SPP SILO WMI] Silo changed, total: 0x%016llx, interesting: 0x%016llx\n",
            gLoggerCtxState.SiloTotal, gLoggerCtxState.SiloInteresting);
    }

    return INT_STATUS_SUCCESS;

}


static INTSTATUS
IntWinInfHookSppHookWmiSiloPtr(
    void
    )
///
/// @brief  Establishes the EPT hook on EtwpDebuggerDataSilo on the pointer to WMI_LOGGER_CONTEXT.
///
/// If OPT_SET_WMI_SPP_STATS it will also set an EPT hook in order to measure the total
/// number of writes in the SPP region in which the WMI_LOGGER_CONTEXT pointer resides.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED If the hook is already established.
/// @retval #INT_STATUS_NOT_SUPPORTED   If SPP is not supported, as without SPP mechanism the hook
///                                     will induce a major performance impact.
///
{
    INTSTATUS status;

    if (NULL != gLoggerCtxState.SiloHookObject || NULL != gLoggerCtxState.SiloHookObjectStats)
    {
        ERROR("[ERROR] Silo hook already initialized: %p %p\n", gLoggerCtxState.SiloHookObject,
              gLoggerCtxState.SiloHookObjectStats);
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    if (gGuest.SupportSPP)
    {
        // the WMI_LOGGER_CONTEXT can (and will) relocate from EtwDebuggerDataSilo
        // this will cause a very high amount of writes to something that is no more a WMI_LOGGER_CONTEXT
        // (or might be, but it is no longer the WMI_LOGGER_CONTEXT used by the kernel...)
        status = IntHookObjectCreate(introObjectTypeKmLoggerContext, gGuest.Mm.SystemCr3,
                                     &gLoggerCtxState.SiloHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookObjectHookRegion(gLoggerCtxState.SiloHookObject,
                                         gGuest.Mm.SystemCr3,
                                         gLoggerCtxState.LoggerGvaInSilo,
                                         gGuest.WordSize,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinInfHookSppViolationCallbackWmiPtrChanged,
                                         NULL,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            return status;
        }

#ifdef OPT_SET_WMI_SPP_STATS
        status = IntHookObjectCreate(introObjectTypeKmLoggerContext,
                                     gGuest.Mm.SystemCr3, &gLoggerCtxState.SiloHookObjectStats);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookObjectHookRegion(gLoggerCtxState.SiloHookObjectStats,
                                         gGuest.Mm.SystemCr3,
                                         gLoggerCtxState.LoggerGvaInSilo & 0xFFFFFFFFFFFFFF80,
                                         0x80,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinInfHookSppWmiSiloStatsCallback,
                                         NULL,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            return status;
        }
#endif

        LOG("[INFO] Successfully hooked silo ptr\n");
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_SUPPORTED;
}


static INTSTATUS
IntWinInfHookIntegritySendAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief  Sends an integrity alert when a modification on WMI_LOGGER_CONTEXT's GetCpuClock
///         has been detected through the integrity mechanism.
///
/// Every second the GetCpuClock field inside the WMI_LOGGER_CONTEXT will be checked to ensure
/// that no modification was made on it, in the case when SPP is not supported, as normal EPT
/// hooks will induce a major performance impact. If a modification was detected, the exceptions
/// will be consulted, and if the modification is considered malicious, an alert will be sent
/// through this function.
///
/// @param[in]  Victim      The #EXCEPTION_VICTIM_ZONE describing the victim, in this case the
///                         Circular Kernel Context Logger.
/// @param[in]  Originator  The #EXCEPTION_KM_ORIGINATOR describing the originator who made
///                         the write, in this case a kernel driver.
/// @param[in]  Action      The action taken by the exception mechanism.
/// @param[in]  Reason      The reason why the exception mechanism took the given action.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PEVENT_INTEGRITY_VIOLATION pIntViol;

    pIntViol = &gAlert.Integrity;
    memzero(pIntViol, sizeof(*pIntViol));

    pIntViol->BaseAddress = Victim->Integrity.StartVirtualAddress;
    pIntViol->VirtualAddress = Victim->Integrity.StartVirtualAddress + Victim->Integrity.Offset;
    pIntViol->Victim.Type = Victim->Object.Type;
    pIntViol->Size = Victim->Integrity.TotalLength;

    pIntViol->Header.Flags |= IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Reason);

    // Force de-activation of ALERT_FLAG_NOT_RING0. We're always in ring0.
    pIntViol->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    if (gGuest.KernelBetaDetections)
    {
        pIntViol->Header.Flags |= ALERT_FLAG_BETA;
    }

    pIntViol->Header.Flags |= ALERT_FLAG_ASYNC;

    pIntViol->Header.Action = Action;
    pIntViol->Header.Reason = Reason;
    pIntViol->Header.MitreID = idRootkit;

    memcpy(pIntViol->Victim.Name, VICTIM_CIRCULAR_KERNEL_CTX_LOGGER, sizeof(VICTIM_CIRCULAR_KERNEL_CTX_LOGGER));

    IntAlertFillWriteInfo(Victim, &pIntViol->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &pIntViol->Originator.Module);

    IntAlertFillCpuContext(FALSE, &pIntViol->Header.CpuContext);

    // We can't know from what CPU the write was, but we know where the integrity check failed
    pIntViol->Header.CpuContext.Valid = FALSE;

    IntAlertFillWinProcessByCr3(pIntViol->Header.CpuContext.Cr3, &pIntViol->Header.CurrentProcess);

    IntAlertFillVersionInfo(&pIntViol->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViol, sizeof(*pIntViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookIntegrityHandleWrite(
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _In_opt_ INTEGRITY_REGION *IntegrityRegion,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief  Handles a detected modification on GetCpuClock field inside the WMI_LOGGER_CONTEXT
///         structure.
///
/// Whenever a modification is detected on GetCpuClock, either by the integrity mechanism or when
/// the WMI_LOGGER_CONTEXT is relocated by changing the pointer in the EtwDebuggerDataSilo structure,
/// this function will be called in order to check the exceptions and, if the exception mechanism
/// decides that the modification is malicious, it will send an alert through a subsequent call
/// to #IntWinInfHookIntegritySendAlert. Note that it has been observed on Windows 20h1 that
/// the GetCpuClock is not a kernel pointer, but rather an index to an array of functions which can
/// be called when GetCpuClock is needed. For now, this case is not handled.
///
/// @param[in]  OldValue                The known value of GetCpuClock before the modification has been detected.
/// @param[in]  NewValue                The current modified value of GetCpuClock, which triggered the integrity
///                                     mechanism or was detected on relocation.
/// @param[in] IntegrityRegion          The #INTEGRITY_REGION object for which the integrity mechanism has detected
///                                     a modification. Will be NULL when called on WMI_LOGGER_CONTEXT relocation.
/// @param[in, out] Action              A pointer to an #INTRO_ACTION which will be completed by this function
///                                     based on the decision of the exception mechanism.
///
/// @retval #INT_STATUS_SUCCESS         On success or when the current value does not reside in kernel.
///
{
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    INTSTATUS status;
    DWORD offset = 0;
    BOOLEAN exitAfterInformation = FALSE;
    INTRO_ACTION_REASON reason;

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    // Bail out if the new value is not a kernel pointer. As observer on 20h1, it is equal to 3 at start. We shouldn't
    // consider it malicious if it doesn't point somewhere in the kernel space.
    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, NewValue))
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsKern);

    if (NULL != IntegrityRegion)
    {
        status = IntExceptGetVictimIntegrity(IntegrityRegion, &offset, &victim);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting integrity zone: 0x%08x\n", status);
            reason = introReasonInternalError;
            exitAfterInformation = TRUE;
        }
    }
    else
    {
        // If we have a NULL IntegrityRegion it means that it is a modification due to a relocation
        // of the WMI_LOGGER_CONTEXT, so we will complete the victim with some well chosen values.

        victim.Integrity.Offset = 0;
        victim.Integrity.StartVirtualAddress = gLoggerCtxState.WmiLoggerCtx +
                                               WIN_KM_FIELD(Ungrouped, WmiGetClockOffset);
        victim.Integrity.TotalLength = gGuest.WordSize;
        victim.ZoneType = exceptionZoneIntegrity;
        victim.Object.Type = introObjectTypeKmLoggerContext;
        victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
        victim.WriteInfo.OldValue[0] = OldValue;
        victim.WriteInfo.NewValue[0] = NewValue;
        victim.WriteInfo.AccessSize = gGuest.WordSize;
    }

    status = IntExceptGetOriginatorFromModification(&victim, &originator);
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

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventIntegrityViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Action, &reason))
    {
        IntWinInfHookIntegritySendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_LOGGER_CONTEXT, Action);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookGetCpuClockIntegrityCallback(
    _In_ void *IntegrityRegion
    )
///
/// @brief  Function called whenever a modification has been detected through the integrity mechanism
///         on WMI_LOGGER_CONTEXT's GetCpuClock field.
///
/// @param[in]  IntegrityRegion The #INTEGRITY_REGION object associated with the protected field.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD getCpuClock = 0;
    INTRO_ACTION action = introGuestAllowed;

    status = IntKernVirtMemRead(gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                gGuest.WordSize,
                                &getCpuClock,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n",
              gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset), status);
        return status;
    }

    if (gLoggerCtxState.CurrentGetCpuClock == getCpuClock)
    {
        IntIntegrityRecalculate(IntegrityRegion);
        return INT_STATUS_SUCCESS;
    }

    status = IntWinInfHookIntegrityHandleWrite(gLoggerCtxState.CurrentGetCpuClock, getCpuClock,
                                               IntegrityRegion, &action);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookIntegrityHandleWrite failed: 0x%08x\n", status);
        return status;
    }

    if (introGuestAllowed == action)
    {
        IntIntegrityRecalculate(IntegrityRegion);
        gLoggerCtxState.CurrentGetCpuClock = getCpuClock;
    }
    else if (introGuestNotAllowed == action)
    {
        LOG("[ROOTKIT] Change of GetCpuClock: New value: 0x%016llx Old value: 0x%016llx\n", getCpuClock,
            gLoggerCtxState.CurrentGetCpuClock);

        IntPauseVcpus();

        status = IntKernVirtMemWrite(gLoggerCtxState.WmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                     gGuest.WordSize,
                                     &gLoggerCtxState.CurrentGetCpuClock);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinInfHookSiloWmiPtrIntegrityCallback(
    _In_ void *IntegrityRegion
    )
///
/// @brief  Integrity callback for modifications over the WMI_LOGGER_CONTEXT pointer inside the
///         EtwDebuggerDataSilo structure.
///
/// When a modification is detected on the WMI_LOGGER_CONTEXT pointer, this function will be called.
/// It is needed to intercept modifications on this pointer in order to find when the WMI_LOGGER_CONTEXT
/// is relocated, so that the integrity protection on GetCpuClock can be adjusted if needed. Also, it is
/// a measure of protection in case of malicious relocations. For example, a malicious driver can change
/// the pointer to a structure having the GetCpuClock function pointer already hooked. For this reasons,
/// checks are made in order to determine whether the relocation is a malicious or not, and an alert will
/// be sent if, after consulting the exception mechanism, it is decided that it is malicious.
/// Note: Even if the relocation took place between two timer calls, and writes were done over the old
/// WMI_LOGGER_CONTEXT virtual address, which is now most probably used for other purposes inside the
/// guest, the EtwDebuggerDataSilo integrity callback will always be called before, as it is added in
/// the integrity hook list before. This will ensure that this function can remove the GetCpuClock
/// integrity region before actually checking modifications over it, so that we avoid false positives.
///
/// @param[in]  IntegrityRegion The #INTEGRITY_REGION object associated with the region containing the
///                             WMI_LOGGER_CONTEXT pointer inside the EtwDebuggerDataSilo structure.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD wmiLoggerCtx = 0;
    BOOLEAN shouldSkipHook = FALSE;

    if (NULL != gLoggerCtxState.WmiLoggerIntegrityObject)
    {
        status = IntIntegrityDeleteRegion(gLoggerCtxState.WmiLoggerIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
            return status;
        }

        gLoggerCtxState.WmiLoggerIntegrityObject = NULL;
    }

    status = IntKernVirtMemRead(gLoggerCtxState.LoggerGvaInSilo, gGuest.WordSize, &wmiLoggerCtx, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    // If the first bit is set, then at the very first call of EtwpLogKernelEvent, the kernel will call
    // nt!EtwpCloseLogger on the WMI_LOGGER_CONTEXT, as it means that it is no longer a valid context and is waiting
    // to be closed.
    shouldSkipHook = (wmiLoggerCtx & 1) || wmiLoggerCtx == 0;

    wmiLoggerCtx &= WMI_PTR_MASK;

    LOG("[INFO] WMI_LOGGER_CONTEXT relocated from 0x%016llx to %016llx (shouldSkipHook: %s)\n",
        gLoggerCtxState.WmiLoggerCtx, wmiLoggerCtx, shouldSkipHook ? "TRUE" : "FALSE");

    gLoggerCtxState.WmiLoggerCtx = wmiLoggerCtx;

    // NOTE: (This is handled on the shouldSkipHook case, but it is worth mentioning)
    // We may end up here checking some temporary structure which does not contain GetCpuClock at it's known location
    // For now we can just let it be this way, we can either check for the bit 1 to be set of the pointer
    // but bare in mind that it is always set when the temporary structure is written, but sometimes it is set even if
    // there is no temporary structure (and nobody keeps someone to set the first bit anyway).
    if (shouldSkipHook)
    {
        goto _recalculate_and_exit;
    }

    // First verify here if the new WMI_LOGGER_CONTEXT.GetCpuClock resides in kernel. If it doesn't, we will send an
    // integrity alert and don't add the new integrity region. If we know the real WMI_LOGGER_CONTEXT.GetCpuClock from
    // the kernel we will overwrite it and then protect the new region. But if something fails, we shouldn't protect
    // the relocated structure.
    status = IntWinInfCheckCtxLoggerOnRelocation();
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinInfCheckCtxLoggerOnRelocation failed: 0x%08x\n", status);
        goto _recalculate_and_exit;
    }

    status = IntIntegrityAddRegion(wmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                   gGuest.WordSize,
                                   introObjectTypeKmLoggerContext,
                                   NULL,
                                   IntWinInfHookGetCpuClockIntegrityCallback,
                                   TRUE,
                                   &gLoggerCtxState.WmiLoggerIntegrityObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
        return status;
    }

_recalculate_and_exit:
    IntIntegrityRecalculate(IntegrityRegion);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookGetEtwpDebuggerData(
    _Out_ QWORD *EtwpDebuggerData
    )
///
/// @brief  Finds the EtwpDebuggerData guest virtual address in the guest's kernel.
///
/// This function will search for the pattern "0x2c 0x08 0x04 0x38 0x0c" inside the Windows kernel, first in the .data
/// section, then in .rdata section, then in every section of the kernel if there was no address found in the first
/// two. This is needed because on some Windows versions, such as Windows 7 x86, it seems that the EtwpDebuggerData
/// structure resides at the end of .text section.
///
/// @param[out] EtwpDebuggerData    The returned virtual address of the EtwpDebuggerData structure.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    WIN_UNEXPORTED_FUNCTION_PATTERN pattern =
    {
        .SectionHint = ".data",
        .Signature =
        {
            .Length = 5,
            .Offset = 0,
            .Pattern =
            {
                0x2c,
                0x08,
                0x04,
                0x38,
                0x0c
            },
        },
    };
    DWORD etwpDbgDataRva = 0;
    QWORD etwpDbgDataGva;

    // If it was already initialized and we retried the initialization, then don't do the whole searching again,
    // it won't change
    if (0 != gLoggerCtxState.EtwDbgDataGva)
    {
        *EtwpDebuggerData = gLoggerCtxState.EtwDbgDataGva;
        return INT_STATUS_SUCCESS;
    }

    status = IntPeFindFunctionByPatternInBuffer(gWinGuest->KernelBuffer, gWinGuest->KernelBufferSize, &pattern, FALSE,
                                                &etwpDbgDataRva);
    if (!INT_SUCCESS(status))
    {
        memcpy(pattern.SectionHint, ".rdata", sizeof(".rdata"));

        status = IntPeFindFunctionByPatternInBuffer(gWinGuest->KernelBuffer, gWinGuest->KernelBufferSize,
                                                    &pattern, FALSE, &etwpDbgDataRva);
        if (!INT_SUCCESS(status))
        {
            // On some versions of Win7 this structure seems to be randomly put at the end of .text ...
            status = IntPeFindFunctionByPatternInBuffer(gWinGuest->KernelBuffer, gWinGuest->KernelBufferSize,
                                                        &pattern, TRUE, &etwpDbgDataRva);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPeFindFunctionByPattern failed: 0x%08x\n", status);
                return status;
            }
        }
    }

    // The signature resides at offset 2 from the EtwDebuggerData structure, so we have to decrease 2.
    // We cast to signed INT32 the WIN_KM_FIELD as it is received from CAMI as a DWORD. But we want to decrease,
    // so treat it as signed.
    etwpDbgDataRva += (INT32)WIN_KM_FIELD(Ungrouped, EtwSignatureOffset);

    etwpDbgDataGva = gGuest.KernelVa + etwpDbgDataRva;

    LOG("[INFO] Found EtwpDebuggerData at RVA 0x%08x -> ptr at 0x%016llx\n", etwpDbgDataRva, etwpDbgDataGva);

    gLoggerCtxState.EtwDbgDataGva = etwpDbgDataGva;

    *EtwpDebuggerData = etwpDbgDataGva;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookHandleSiloFirstWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief EPT callback to handle the first write over EtwpDebuggerData, where the pointer
///        of EtwDebuggerDataSilo should be.
///
/// On some Windows versions, the EtwpDebuggerDataSilo is not initialized at boot time
/// directly, but a little bit later. For this purpose, we hook the EtwpDebuggerData structure
/// in order to see when the EtwpDebuggerDataSilo pointer is written inside it. At this point
/// we can continue infinity hook protection initialization on the next timer tick.
///
/// @param[in]  Context         The user provided context set when the hook was established.
/// @param[in]  Hook            The EPT hook object for which the callback was called.
/// @param[in]  Address         The address on which the EPT violation occurred.
/// @param[in, out]  Action     A pointer to an #INTRO_ACTION, which will always be set
///                             to introGuestAllowed, since this is a notification callback
///                             rather than a protection callback.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    OPERAND_VALUE writtenValue = { 0 };

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    *Action = introGuestAllowed;

    status = IntDecGetWrittenValueFromInstruction(&gVcpu->Instruction, &gVcpu->Regs, 0, &writtenValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecGetWrittenValueFromInstruction failed: 0x%08x\n", status);
        goto _exit;
    }

    if (writtenValue.Value.QwordValues[0] == 0)
    {
        goto _exit;
    }

    // We'll initialize on the next timer tick.
    gLoggerCtxState.FailedToInitialize = FALSE;

    status = IntHookGvaRemoveHook((HOOK_GVA **)&gLoggerCtxState.FirstSiloWriteHookObject, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        return status;
    }

_exit:
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookGetCircularCtxLogger(
    _Out_ QWORD *KernelCtxLogger
    )
///
/// @brief Fetches the WMI_LOGGER_CONTEXT pointer from EtwDebuggerDataSilo, if possible.
///
/// Firstly, this function will get the EtwpDebuggerData structure, by searching it by a
/// hard coded pattern through a call to #IntWinInfHookGetEtwpDebuggerData. After that,
/// it will check the EtwDebuggerDataSilo field in this structure. If it is 0, then an
/// EPT hook will be set in order to be notified when this field is written and continue
/// initialization. If it is initialized, then the WMI_LOGGER_CONTEXT will be fetched,
/// which is the third pointer in the EtwpDebuggerDataSilo structure.
///
/// @param[out] KernelCtxLogger The returned pointer to the WMI_LOGGER_CONTEXT structure.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT    When the EtwpDebuggerDataSilo is not yet
///                                             initialized.
///
{
    INTSTATUS status;
    QWORD etwpDbgDataGva = 0;
    QWORD etwpDbgDataSiloPtrGva;
    QWORD etwpDbgDataSilo = 0;
    QWORD ctxLoggerPtrGva;
    QWORD ctxLoggerGva = 0;

    status = IntWinInfHookGetEtwpDebuggerData(&etwpDbgDataGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookGetEtwpDebuggerData failed: 0x%08x\n", status);
        return status;
    }

    etwpDbgDataSiloPtrGva = etwpDbgDataGva + WIN_KM_FIELD(Ungrouped, EtwDbgDataSiloOffset);

    status = IntKernVirtMemRead(etwpDbgDataSiloPtrGva, gGuest.WordSize, &etwpDbgDataSilo, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", etwpDbgDataSiloPtrGva, status);
        return status;
    }

    if (0 == etwpDbgDataSilo)
    {
        // We mark failed to initialize so that we don't retry again and again as we expect the write hook to take place
        gLoggerCtxState.FailedToInitialize = TRUE;

        LOG("[INFO] EtwpDbgDataSilo is 0, will hook for write and init afterwards...\n");

        status = IntHookGvaSetHook(gGuest.Mm.SystemCr3,
                                   etwpDbgDataSiloPtrGva,
                                   gGuest.WordSize,
                                   IG_EPT_HOOK_WRITE,
                                   IntWinInfHookHandleSiloFirstWrite,
                                   NULL,
                                   NULL,
                                   0,
                                   (HOOK_GVA **)&gLoggerCtxState.FirstSiloWriteHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            return status;
        }

        *KernelCtxLogger = 0;
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    ctxLoggerPtrGva = etwpDbgDataSilo + 2ull * gGuest.WordSize;
    LOG("[INFO] Found EtwpDebuggerDataSilo at 0x%016llx -> Logger Ctx Ptr GVA at 0x%016llx\n",
        etwpDbgDataSilo, ctxLoggerPtrGva);

    gLoggerCtxState.LoggerGvaInSilo = ctxLoggerPtrGva;

    status = IntKernVirtMemRead(ctxLoggerPtrGva, gGuest.WordSize, &ctxLoggerGva, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    LOG("[INFO] Found ctx wmi logger GVA: 0x%016llx\n", ctxLoggerGva);

    *KernelCtxLogger = ctxLoggerGva;
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinInfHookGetWmiLoggerGetCpuClock(
    _Out_ QWORD *GetCpuClockGva,
    _Out_opt_ QWORD *WmiLoggerCtx
    )
///
/// @brief  Gets the GetCpuClock field inside the WMI_LOGGER_CONTEXT structure, and the structure
///         guest virtual address if needed.
///
/// The WMI_LOGGER_CONTEXT may not be initialized when this function is called, thus, the GetCpuClock
/// will be considered to be equal to 0, and, during relocation checks, the zero value will mean
/// that the mechanism does not know yet the actual GetCpuClock value.
///
/// @param[out] GetCpuClockGva  The returned value which is present inside WMI_LOGGER_CONTEXT's
///                             GetCpuClock field.
/// @param[out] WmiLoggerCtx    The guest virtual address of the WMI_LOGGER_CONTEXT. This parameter
///                             is optional.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    QWORD wmiLoggerCtx = 0;
    QWORD getCpuClock = 0;
    INTSTATUS status;
    KERNEL_DRIVER *pDrv = NULL;

    status = IntWinInfHookGetCircularCtxLogger(&wmiLoggerCtx);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookGetCircularCtxLogger failed: 0x%08x\n", status);
        return status;
    }
    else if (INT_STATUS_NOT_INITIALIZED_HINT == status)
    {
        *GetCpuClockGva = 0;

        if (NULL != WmiLoggerCtx)
        {
            *WmiLoggerCtx = 0;
        }

        return status;
    }

    if ((wmiLoggerCtx & 1) || (wmiLoggerCtx & WMI_PTR_MASK) == 0)
    {
        goto _skip_read;
    }

    status = IntKernVirtMemRead(wmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                gGuest.WordSize, &getCpuClock, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n",
              wmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset), status);
        return status;
    }

    LOG("[INFO] GetCpuClock() at 0x%016llx\n", getCpuClock);

    pDrv = IntDriverFindByAddress(getCpuClock);
    if (NULL == pDrv || pDrv->BaseVa != gGuest.KernelVa)
    {
        WARNING("[WARNING] GetCpuClock does not reside inside the kernel!\n");

        // We have the case where the initial GetCpuClock doesn't reside inside the kernel. We can't do anything
        // but send an alert to notify that this is an unusual case. However, by forcing the current getCpuClock to 0
        // an alert will be sent while checking the "relocation from 0 to something".
        getCpuClock = 0;
    }

_skip_read:
    *GetCpuClockGva = getCpuClock;

    if (NULL != WmiLoggerCtx)
    {
        *WmiLoggerCtx = wmiLoggerCtx;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinInfHookProtect(
    void
    )
///
/// @brief This function initializes protection against infinity hook mechanism.
///
/// Called on timer once every second, it will try to initialize the infinity hook protection
/// mechanism. If the initialization has already failed, the function will bail out. Note that
/// this function might be called multiple times since EtwpDebuggerDataSilo may not be initialized
/// and once everything is set up, it will try once again to initialize protection on timer when
/// a write to the pointer in order to initialize it has been made.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT    When the protection is already initialized or it already
///                                                 failed to initialize.
/// @retval #INT_STATUS_NOT_NEEDED_HINT When, based on the current options, the infinity hook protection
///                                     is not activated.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT    When we don't have yet a kernel driver, thus the protection
///                                             cannot be established yet.
/// @retval #INT_STATUS_ALREADY_INITIALIZED     When the hooks are already established but the protection
///                                             is not considered initialized. Indicates an error in properly
///                                             setting the #gLoggerCtxState fields.
///
{
    INTSTATUS status;
    QWORD getCpuClock = 0;
    QWORD wmiLoggerCtx = 0;

    if (__likely(gLoggerCtxState.Initialized))
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LOGGER_CONTEXT))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // We don't want to init until we have the kernel driver, as on timer, we can wait for swapmems to take place
    // and we end up hooking unwanted stuff in some corner cases.
    if (__unlikely(NULL == gGuest.KernelDriver))
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    // We don't have to bother retrying to initialize on timer if we failed to init already
    if (__unlikely(gLoggerCtxState.FailedToInitialize))
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    status = IntWinInfHookGetWmiLoggerGetCpuClock(&getCpuClock, &wmiLoggerCtx);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinInfHookGetWmiLoggerGetCpuClock failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }
    else if (INT_STATUS_NOT_INITIALIZED_HINT == status)
    {
        return status;
    }

    gLoggerCtxState.WmiLoggerCtx = wmiLoggerCtx;
    gLoggerCtxState.CurrentGetCpuClock = getCpuClock;

    if (gGuest.SupportSPP)
    {
        status = IntWinInfHookSppHookWmiSiloPtr();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinInfHookSppHookWmiSiloPtr failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // We didn't have yet a WMI_LOGGER_CONTEXT, so basically it is a relocation from 0 to the current one
        status = IntWinInfCheckCtxLoggerOnRelocation();
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinInfCheckCtxLoggerOnRelocation failed: 0x%08x\n", status);
            goto _skip_hooking_spp;
        }

        status = IntWinInfHookHookSppWmiGetClock();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinInfHookHookSppWmiGetClock failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

_skip_hooking_spp:
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        // First hook the EtwDebuggerDataSilo to verify any change on the WMI_LOGGER_CONTEXT pointer

        if (NULL != gLoggerCtxState.SiloIntegrityObject || NULL != gLoggerCtxState.WmiLoggerIntegrityObject)
        {
            ERROR("[ERROR] Wmi integrity hook already initialized! %p %p\n",
                  gLoggerCtxState.SiloIntegrityObject, gLoggerCtxState.WmiLoggerIntegrityObject);

            status = INT_STATUS_ALREADY_INITIALIZED;
            goto cleanup_and_exit;
        }

        status = IntIntegrityAddRegion(gLoggerCtxState.LoggerGvaInSilo,
                                       gGuest.WordSize,
                                       introObjectTypeKmLoggerContext,
                                       NULL,
                                       IntWinInfHookSiloWmiPtrIntegrityCallback,
                                       TRUE,
                                       &gLoggerCtxState.SiloIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // We didn't have yet a WMI_LOGGER_CONTEXT, so basically it is a relocation from 0 to the current one
        status = IntWinInfCheckCtxLoggerOnRelocation();
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinInfCheckCtxLoggerOnRelocation failed: 0x%08x\n", status);
            goto _skip_hooking;
        }

        // Now hook the currently found WMI_LOGGER_CONTEXT.CpuGetClock
        status = IntIntegrityAddRegion(wmiLoggerCtx + WIN_KM_FIELD(Ungrouped, WmiGetClockOffset),
                                       gGuest.WordSize,
                                       introObjectTypeKmLoggerContext,
                                       NULL,
                                       IntWinInfHookGetCpuClockIntegrityCallback,
                                       TRUE,
                                       &gLoggerCtxState.WmiLoggerIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

_skip_hooking:
        status = INT_STATUS_SUCCESS;
    }

    gLoggerCtxState.Initialized = TRUE;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        // If we failed to initialize once, we won't magically initialize afterwards...
        gLoggerCtxState.FailedToInitialize = TRUE;

        IntWinInfHookUnprotect();
    }

    return status;
}


INTSTATUS
IntWinInfHookUnprotect(
    void
    )
///
/// @brief  Removes the protection against infinity hook.
///
/// It will remove all the established hooks, and reset the state. Note that the FailedToInitialize
/// field in #gLoggerCtxState will remain in the same value, in order to avoid retrying to establish
/// the hooks if the protection failed if there are protection flags changes which disable and then
/// re-enable the infinity hook protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    BOOLEAN bFailedToInit;

    if (NULL != gLoggerCtxState.WmiLoggerIntegrityObject)
    {
        status = IntIntegrityRemoveRegion(gLoggerCtxState.WmiLoggerIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
            return status;
        }

        gLoggerCtxState.WmiLoggerIntegrityObject = NULL;
    }

    if (NULL != gLoggerCtxState.SiloIntegrityObject)
    {
        status = IntIntegrityRemoveRegion(gLoggerCtxState.SiloIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
            return status;
        }

        gLoggerCtxState.SiloIntegrityObject = NULL;
    }

    if (NULL != gLoggerCtxState.WmiLoggerHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.WmiLoggerHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != gLoggerCtxState.WmiLoggerHookObjectStats)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.WmiLoggerHookObjectStats, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != gLoggerCtxState.SiloHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.SiloHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != gLoggerCtxState.SiloHookObjectStats)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLoggerCtxState.SiloHookObjectStats, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
            return status;
        }
    }

    if (NULL != gLoggerCtxState.FirstSiloWriteHookObject)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&gLoggerCtxState.FirstSiloWriteHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            return status;
        }
    }

    // Reset the state but keep the FailedToInitialize boolean the same as before.
    bFailedToInit = gLoggerCtxState.FailedToInitialize;

    memzero(&gLoggerCtxState, sizeof(gLoggerCtxState));

    gLoggerCtxState.FailedToInitialize = bFailedToInit;

    return INT_STATUS_SUCCESS;
}
