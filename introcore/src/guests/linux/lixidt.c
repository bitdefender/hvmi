/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixidt.h"
#include "alerts.h"
#include "hook.h"


static INTSTATUS
IntLixIdtWriteHandler(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Called if a write occurs on the protected IDT descriptors.
///
/// If a write occurs the exceptions mechanism is used to decide if the write should be allowed.
/// If the write is not allowed an EPT violation event is sent to the integrator.
///
/// @param[in]  Context     The context provided by the caller.
/// @param[in]  Hook        The GPA hook associated to this callback.
/// @param[in]  Address     The GPA address that was accessed.
/// @param[out] Action      The action that must be taken.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_4      If the provided Action is null.
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    INTRO_ACTION_REASON reason = introReasonUnknown;
    QWORD idtBase;
    QWORD idtLimit;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    status = IntGuestGetIdtFromGla(gVcpu->Gla, &idtBase, &idtLimit);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestGetIdtFromGla failed: 0x%08x, the write on 0x%016llx (gpa 0x%016llx) "
              "from cpu %d seems to be outside any idt!\n", status, gVcpu->Gla, gVcpu->Gpa, gVcpu->Index);

        *Action = introGuestAllowed;

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
    }

    status = IntExceptGetVictimEpt(&idtBase,
                                   gVcpu->Gpa,
                                   gVcpu->Gla,
                                   introObjectTypeIdt,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        reason = introReasonInternalError;
    }

    IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_IDT, Action, &reason))
    {
        EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;
        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = introReasonNoException;
        pEptViol->Header.MitreID = idRootkit;

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_IDT, reason);

        IntAlertFillLixCurrentProcess(&pEptViol->Header.CurrentProcess);

        if (originator.Original.Driver != NULL)
        {
            IntAlertFillLixKmModule(originator.Original.Driver, &pEptViol->Originator.Module);
        }
        if (originator.Return.Driver != NULL)
        {
            IntAlertFillLixKmModule(originator.Return.Driver, &pEptViol->Originator.ReturnModule);
        }

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        IntAlertFillCodeBlocks(originator.Original.Rip, gVcpu->Regs.Cr3, FALSE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        IntAlertFillVersionInfo(&pEptViol->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_IDT, Action);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixIdtProtectOnCpu(
    _In_ DWORD CpuNumber
    )
///
/// @brief Activates protection for the provided CPU's IDT.
///
/// This function hooks the first 0x20 entries and the 80th entry from the provided CPU's IDT using EPT. If the current
/// guest virtual address of the IDT is already hooked that hook-object will be used.
/// The Linux IDT has the same guest virtual address on all CPUs.
///
/// @param[in]  CpuNumber   The number of the CPU for witch the IDT will be protected.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_INITIALIZED  If the IDT of the provided CPU is not initialized.
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD idtBase;
    WORD idtLimit;

    idtBase = gGuest.VcpuArray[CpuNumber].IdtBase;
    if (0 == idtBase)
    {
        status = IntIdtFindBase(CpuNumber, &idtBase, &idtLimit);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        gGuest.VcpuArray[CpuNumber].IdtBase = idtBase;
        gGuest.VcpuArray[CpuNumber].IdtLimit = idtLimit;
    }

    if (0 == idtBase)
    {
        WARNING("[WARNING] Cpu %d has no IDT yet!\n", CpuNumber);
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (gGuest.VcpuArray[CpuNumber].IdtHookObject == NULL)
    {
        status = IntHookObjectCreate(introObjectTypeIdt, 0, &gGuest.VcpuArray[CpuNumber].IdtHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        for (DWORD indexCpu = 0; indexCpu < gGuest.CpuCount; ++indexCpu)
        {
            if (CpuNumber == indexCpu)
            {
                continue;
            }

            if (gGuest.VcpuArray[indexCpu].IdtBase == idtBase)
            {
                TRACE("[HOOK] IDT already hooked -> @ %llx for CPU %d.\n", idtBase, CpuNumber);
                return INT_STATUS_SUCCESS;
            }
        }
    }

    TRACE("[HOOK] Hooking IDT (0x20 entries) for CPU %d @ 0x%016llx\n", CpuNumber, idtBase);

    status = IntHookObjectHookRegion(gGuest.VcpuArray[CpuNumber].IdtHookObject,
                                     0,
                                     idtBase,
                                     IDT_DESC_SIZE64 * 0x20,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixIdtWriteHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking IDT at 0x%016llx for CPU %d: 0x%08x\n", idtBase, CpuNumber, status);
        return status;
    }

    TRACE("[HOOK] Hooking IDT Int80 for CPU %d @ 0x%016llx\n", CpuNumber, idtBase + IDT_DESC_SIZE64 * 0x80);

    status = IntHookObjectHookRegion(gGuest.VcpuArray[CpuNumber].IdtHookObject,
                                     0,
                                     idtBase + IDT_DESC_SIZE64 * 0x80,
                                     IDT_DESC_SIZE64,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixIdtWriteHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking entry 80 of IDT at 0x%016llx for CPU %d: 0x%08x\n", idtBase, CpuNumber, status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixIdtProtectAll(
    void
    )
///
/// @brief Activates protection for IDT on all CPUs.
///
/// @retval #INT_STATUS_SUCCESS          On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT  In case there are no CPU's
///
{
    INTSTATUS failStatus = INT_STATUS_NOT_NEEDED_HINT;

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        INTSTATUS status = IntLixIdtProtectOnCpu(i);
        if (!INT_SUCCESS(status))
        {
            failStatus = status;
            continue;
        }
    }

    return failStatus;
}


INTSTATUS
IntLixIdtUnprotectAll(
    void
    )
///
/// @brief Disable protection for IDT on all CPUs.
///
/// @retval #INT_STATUS_SUCCESS          On success.
///
{
    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        if (gGuest.VcpuArray[i].IdtHookObject)
        {
            INTSTATUS status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gGuest.VcpuArray[i].IdtHookObject, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed removing idt hook object: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}
