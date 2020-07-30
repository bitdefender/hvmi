/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winpower.h"
#include "guests.h"
#include "ptfilter.h"
#include "vecore.h"
#include "winagent.h"


///
/// @file winpower.c
///
/// @brief This file handles Windows guest power state changes.
///
/// Due to various actions the guest takes when a power state change occurs, introspection engine must be aware
/// of these changes and act accordingly depending on the situation. For example, due to empiric observations,
/// it seems like the Windows operating system remaps NonPagedPool pages when going through a hybrid sleep.
/// This affects the in-guest agents like the VE agent or the PT filter agent, as going through remappings
/// will issue a page fault if there would be executions inside the agent. Other cases like these have been observed
/// both during reboots and shutdowns. For this case we should always remove our agents at the moment of the
/// thus the need of intercepting them through detouring the NtSetSystemPowerState Windows API is required.
/// Other cases involve possible race conditions when hibernating. For example, if we only stop the VAD monitoring
/// then there is the possibility that in the meantime, a new module loads and hooks some user-mode APIs in a
/// protected process. Thus when hibernating, although there is a time frame of at most a couple of seconds where
/// the protection is lost, we disable all protection, thus removing the probability of a race condition to occur.
/// It is worth noting that the NtSetSystemPowerState detour handler will have a small space inside the guest
/// where the introspection engine might decide to insert a spinlock, in order to keep the guest spinning while
/// some operations involving guest execution are done. This is needed to wait for the VE agent unloader/PT filter
/// unloader to finish executing in guest before actually giving the control back to the NtSetSystemPowerState function
/// and let the guest continue the power state change flow.
/// The agent unloader should be given the option #AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE, as a performance tweak,
/// guaranteeing that the agent will start executing directly from the NtSetSystemPowerState detour (e.g. the
/// needed instruction won't be chosen anymore from the syscall handler return, but rather it will be the next
/// instruction from the in-guest RIP, since the NtSetSystemPowerState runs at PASSIVE_LEVEL, it will have the same
/// effect but instead of waiting for a syscall to be executed, it will give the control to the bootstrap immediately).
///


static INTRO_POWER_STATE
IntWinPowFromGuestToIntroPowState(
    _In_ DWORD GuestPowerAction,
    _In_ DWORD GuestPowerState
    )
///
/// @brief Converts in-guest parameters given to NtSetSystemPowerState to an internal introspection used power state.
///
/// @param[in]  GuestPowerAction    The first parameter of NtSetSystemPowerState, which is the requested action.
/// @param[in]  GuestPowerState     The second parameter of NtSetSystemPowerState, being the requested state in which
///                                 the system should enter.
///
/// @returns    An introspection-defined state, see #INTRO_POWER_STATE for more details.
///
{
    // Shutdown: action is "shutdown" or "shutdown off" and state different from hibernate (can be sleep)
    if ((GuestPowerAction == PowerActionShutdown ||
         GuestPowerAction == PowerActionShutdownOff) &&
        GuestPowerState != PowerSystemHibernate)
    {
        return intPowStateShutdown;
    }

    // Reset: power action is reset (we don't care about requested power state, as there is not an edge case
    // like "pressing restart" but system enters on hibernate)
    if (GuestPowerAction == PowerActionShutdownReset)
    {
        return intPowStateReboot;
    }

    // Sleep: action must be sleep and the requested power state must be sleep
    if (GuestPowerAction == PowerActionSleep &&
        GuestPowerState >= PowerSystemSleeping1 &&
        GuestPowerState <= PowerSystemSleeping3)
    {
        return intPowStateSleeping;
    }

    // Hibernate: action can be hibernate/shutdown/shutdown off and the requested power state must be hibernate
    if ((GuestPowerAction == PowerActionHibernate ||
         GuestPowerAction == PowerActionShutdown ||
         GuestPowerAction == PowerActionShutdownOff ||
         GuestPowerAction == PowerActionSleep) &&
        GuestPowerState == PowerSystemHibernate)
    {
        return intPowStateHibernate;
    }

    WARNING("[WARNING] Unknown power action/reason: %d %d!\n", GuestPowerAction, GuestPowerState);

    return intPowStateUnknown;
}


static INTSTATUS
IntWinPowGetRequestedPowerState(
    _Out_ DWORD *RequestedPowerAction,
    _Out_ DWORD *RequestedPowerState
    )
///
/// @brief Gets the parameters of NtSetSystemPowerState depending on OS architecture.
///
/// @param[out]     RequestedPowerAction Contains, on success, the first parameter, the power action requested to the
///                 system.
/// @param[out]     RequestedPowerState Contains, on success the requested power state in which the system must be
///                 after the NtSetSystemPowerState execution.
///
/// @returns         #INT_STATUS_SUCCESS on success; other error INTSTATUS values which #IntKernVirtMemRead may return.
///
{
    if (gGuest.Guest64)
    {
        *RequestedPowerState = (DWORD)gVcpu->Regs.Rdx;
        *RequestedPowerAction = (DWORD)gVcpu->Regs.Rcx;
        return INT_STATUS_SUCCESS;
    }
    else
    {
        DWORD buffer[2];
        INTSTATUS status;

        status = IntKernVirtMemRead(gVcpu->Regs.Rsp + 0x4, 8, buffer, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *RequestedPowerAction = buffer[0];
        *RequestedPowerState = buffer[1];

        return INT_STATUS_SUCCESS;
    }
}


INTSTATUS
IntWinPowEnableSpinWait(
    void
    )
///
/// @brief This function is called in order to re-enable spin waiting in the handler after it was previously disabled.
///
/// @returns #INT_STATUS_SUCCESS on success, or other error INTSTATUS values which may be returned by
/// #IntDetModifyPublicData.
///

{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE hkbuff[4] = { 0xf3, 0x90, 0xeb, 0xfc };

    LOG("[POW-SPIN-WAIT] IntWinPowEnableSpinWait called!\n");

    IntPauseVcpus();

    // 0x6 is the address after the hypercall, where the spinwait is taking place
    // if the handler is ever changed, this must also be changed!
    status = IntDetModifyPublicData(detTagPowerState, hkbuff, sizeof(hkbuff), "spinwait");
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetModifyPublicData failed: 0x%08x\n", status);
    }

    IntResumeVcpus();

    return status;
}


INTSTATUS
IntWinPowDisableSpinWait(
    void
    )
/// @brief This function is called in order to disable spin waiting after everything we needed to be unloaded was done.
///
/// @returns #INT_STATUS_SUCCESS on success, or other error INTSTATUS values which may be returned by
/// #IntDetModifyPublicData.
///
{
    INTSTATUS status;
    BYTE nopbuff[4] = { 0x66, 0x90, 0x66, 0x90 };

    LOG("[POW-SPIN-WAIT] IntWinPowDisableSpinWait called!\n");

    IntPauseVcpus();

    // 0x6 is the address after the hypercall, where the spinwait is taking place
    // if the handler is ever changed, this must also be changed!
    status = IntDetModifyPublicData(detTagPowerState, nopbuff, sizeof(nopbuff), "spinwait");
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetModifyPublicData failed: 0x%08x\n", status);
    }

    IntResumeVcpus();

    return status;
}


static INTSTATUS
IntWinPowHandleEventCommon(
    _In_ INTRO_POWER_STATE PowerState
    )
///
/// @brief This function will be called on any power state change event. Everything that we want to uninit
/// on every power state event will be put here. Note that this function will enable the NtSetSystemPowerState
/// spinwait only if there is something to be done - if there isn't anything it will just return.
///
/// @param[in]   PowerState The power state in which the guest desires to enter
///
/// @returns     #INT_STATUS_NOT_NEEDED_HINT if the state is unknown or there is nothing to be done;
/// other error INTSTATUS values depending on what #IntPtiRemovePtFilter, #IntVeRemoveAgent or #IntWinPowEnableSpinWait
/// might return
///
{
    // Init to not needed hint, so we don't call IntWinPowEnableSpinWait in case INTRO_OPT_IN_GUEST_PT_FILTER
    // or INTRO_OPT_VE is not set
    INTSTATUS status = INT_STATUS_NOT_NEEDED_HINT;

    if (PowerState == intPowStateUnknown)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // INTRO_OPT_IN_GUEST_PT_FILTER and INTRO_OPT_VE are mutually exclusive (this is enforced in IntNewGuestNotification
    // and IntGuestUpdateCoreOptions
    if (gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER)
    {
        LOG("Removing the PT Filter due to power state change...\n");
        status = IntPtiRemovePtFilter(AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE);
    }
    else if (gGuest.CoreOptions.Current & INTRO_OPT_VE)
    {
        LOG("Removing the #VE Agent due to power state change...\n");
        status = IntVeRemoveAgent(AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE);
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPtiRemovePtFilter/IntVeRemoveAgent failed: 0x%08x (options: %016llx)\n",
              status, gGuest.CoreOptions.Current);
    }
    else if (INT_STATUS_NOT_NEEDED_HINT != status)
    {
        // if the unloader was deployed then enable the spinwait
        status = IntWinPowEnableSpinWait();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPowEnableSpinWait failed: 0x%08x\n", status);
        }
    }

    return status;
}


static void
IntWinPowHandleHibernateEvent(
    void
    )
///
/// @brief Callback called when the change of guest power state to hibernate occurs.
///
{
    // Set this on TRUE because in this way we'll block other APIs
    gGuest.EnterHibernate = TRUE;

    IntGuestUpdateCoreOptions(0);
}


INTSTATUS
IntWinPowHandlePowerStateChange(
    _In_ void *Detour
    )
///
/// @brief      Detour callback which is called whenever NtSetSystemPowerState is called, resulting in a hypercall
/// to the introspection engine.
/// @ingroup    group_detours
///
/// @param[in]  Detour The detour object.
///
/// @retval     #INT_STATUS_SUCCESS On success.
/// @retval     #INT_STATUS_NOT_FOUND If an unknown power state change occurs.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD requestedPowerState;
    DWORD requestedPowerAction;
    INTRO_POWER_STATE internalPowerState;

    UNREFERENCED_PARAMETER(Detour);

    status = IntWinPowGetRequestedPowerState(&requestedPowerAction, &requestedPowerState);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] We could not get the requested power state!");
        return status;
    }

    LOG("[POWER-STATE] Entering power state %d, action %d\n", requestedPowerState, requestedPowerAction);

    // For power-state >= sleep, we should disable the PT filter as the following might happen inside the guest:
    // 1. Guest is hybrid sleeping -> it will unmap the PT filter agent, so a BSOD will occur
    // 2. Guest is hibernating -> the agent will remain inside the guest and a BSOD will most likely occur at resume
    //                            also, the name of the patched processes must be restored

    internalPowerState = IntWinPowFromGuestToIntroPowState(requestedPowerAction, requestedPowerState);

    // First do the common handling, then handle more specifically depending on which power state guest tries to get in
    status = IntWinPowHandleEventCommon(internalPowerState);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinPowHandleEventCommon failed: 0x%08x\n", status);
    }

    LOG("[POWER-STATE] Internal power state: %d\n", internalPowerState);

    switch (internalPowerState)
    {
    case intPowStateSleeping:
    case intPowStateShutdown:
    case intPowStateReboot:
    case intPowStateUnknown:
    {
        // We have nothing to do for now
        break;
    }
    case intPowStateHibernate:
    {
        IntWinPowHandleHibernateEvent();

        break;
    }
    default:
    {
        ERROR("[ERROR] Power state %d requested, but we don't have any callback for it!\n", requestedPowerState);
        return INT_STATUS_NOT_FOUND;
    }
    }

    return INT_STATUS_SUCCESS;
}
