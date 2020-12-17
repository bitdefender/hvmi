/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winintobj.h"
#include "integrity.h"
#include "exceptions.h"
#include "alerts.h"
#include "kernvm.h"

///
/// @file winintobj.c
///
/// @brief  This file contains detection logic for interrupt objects in KPRCB, which are used
///         in order to set handlers for unexpected exceptions on most of Windows versions.
///
/// As observed, for some exceptions (for example int 0x15), the control is given to KiIsrLinkage,
/// where the kernel consults KPRCB.InterruptObject[InterruptCode]. If there is no such object
/// associated to the interrupt code, the kernel just dispatches the exception as being unhandled.
/// However, if a KINTERRUPT object is in the given array, the kernel will call DispatchAddress from
/// the given object, which in turn would need to handle the interrupt exit and would pass the control
/// to ServiceRoutine from the given object. Since interrupts can be issued from everywhere, one can
/// forge some object for an unexpected exception in order to gain privileged execution in kernel-mode.
/// For this purpose, we will monitor for the first 0x20 objects in the InterruptObject array from each
/// KPRCB in order to verify relocations or new objects being added when these actions occur. Moreover,
/// the introcore engine will monitor the DispatchAddress and ServiceRoutine fields for each object
/// in the first 0x20, in order to detect and block possible modifications being done with the purpose
/// of detouring the execution when an exception takes place.
///


///
/// @brief  The number of protected interrupt objects.
///
#define INTERRUPT_OBJECT_COUNT      0x20

///
/// @brief  Helper macro for computing the offset of DispatchAddress inside the nt!_KINTERRUPT structure.
///
#define DISPATCH_OFFSET             (gGuest.Guest64 ? FIELD_OFFSET(KINTERRUPT_COMMON64, DispatchAddress) : \
                                                      FIELD_OFFSET(KINTERRUPT_COMMON32, DispatchAddress))
///
/// @brief  Helper macro for computing the offset of ServiceRoutine inside the nt!_KINTERRUPT structure.
///
#define SERVICE_OFFSET              (gGuest.Guest64 ? FIELD_OFFSET(KINTERRUPT_COMMON64, ServiceRoutine) : \
                                                      FIELD_OFFSET(KINTERRUPT_COMMON32, ServiceRoutine))

///
/// @brief  Structure describing a protected interrupt object.
///
typedef struct _INTOBJ_PROT_DESCRIPTOR
{
    void *DispatchIntegrityObject;      ///< The integrity object associated with DispatchAddress.
    void *ServiceIntegrityObject;       ///< The integrity object associated with ServiceRoutine.
    BYTE EntryIndex;                    ///< The index of the current object in the InterruptObject array.
    QWORD ObjectGva;                    ///< The GVA of the current interrupt object.
} INTOBJ_PROT_DESCRIPTOR, *PINTOBJ_PROT_DESCRIPTOR;


///
/// @brief  Structure describing the protected InterruptObject array for a KPRCB associated with a CPU.
///
typedef struct _INTOBJ_PERPROC_DESCRIPTOR
{
    /// @brief  Array containing protection descriptors for each protected interrupt object in the array.
    INTOBJ_PROT_DESCRIPTOR IntObjDescriptors[INTERRUPT_OBJECT_COUNT];
    void *ObjectIntegrityObject;        ///<    The integrity object associated with the monitorized array.
} INTOBJ_PERPROC_DESCRIPTOR, *PINTOBJ_PERPROC_DESCRIPTOR;

/// @brief  Global array containing the per CPU protection descriptors for each InterruptObject array.
INTOBJ_PERPROC_DESCRIPTOR *gDescriptors;


static INTSTATUS
IntWinIntObjSendIntegrityAlert(
    _In_ INTOBJ_PROT_DESCRIPTOR *Descriptor,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief  Sends an #introEventIntegrityViolation alert for a modified Interrupt Object entry.
///
/// @param[in]  Descriptor  The #INTOBJ_PROT_DESCRIPTOR descriptor associated with the modified object.
/// @param[in]  Victim      The victim information, as obtained from the exception mechanism.
/// @param[in]  Originator  Originator information, as obtained from the exception mechanism.
/// @param[in]  Action      The action that was taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    EVENT_INTEGRITY_VIOLATION *pEvent;

    pEvent = &gAlert.Integrity;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->BaseAddress = Descriptor->ObjectGva;
    pEvent->VirtualAddress = Descriptor->ObjectGva;
    pEvent->Size = 2 * gGuest.WordSize;
    pEvent->Victim.IdtEntry = Descriptor->EntryIndex;
    pEvent->Victim.Type = introObjectTypeInterruptObject;

    // No valid CPU context and no valid current process can be obtained for this, as it is
    // an integrity alert.
    pEvent->Header.CpuContext.Valid = FALSE;
    pEvent->Header.CurrentProcess.Valid = FALSE;

    pEvent->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_INTERRUPT_OBJ, Reason);
    pEvent->Header.Flags |= ALERT_FLAG_ASYNC;

    pEvent->Header.Action = Action;
    pEvent->Header.Reason = Reason;
    pEvent->Header.MitreID = idRootkit;

    memcpy(pEvent->Victim.Name, VICTIM_INTERRUPT_OBJECT, sizeof(VICTIM_INTERRUPT_OBJECT));

    IntAlertFillWriteInfo(Victim, &pEvent->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &pEvent->Originator.Module);

    IntAlertFillVersionInfo(&pEvent->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIntObjHandleModification(
    _In_ INTOBJ_PROT_DESCRIPTOR *Descriptor,
    _In_ QWORD ObjectGva,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles the modification of an interrupt object.
///
/// This function handles the detected modification and takes an action after consulting the
/// exception mechanism. Note that this function can be called either when an object has been
/// relocated, or when the object has been modified.
///
/// @param[in]  Descriptor  The #INTOBJ_PROT_DESCRIPTOR descriptor associated with the modified object.
/// @param[in]  ObjectGva   The virtual address of the object. Note that, when an object is relocated,
///                         this will contain a different address than what is protected through the
///                         integrity objects associated in the given descriptor.
/// @param[out] Action      The action that is going to be decided by this function.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTEGRITY_REGION *dispatchReg = (INTEGRITY_REGION *)Descriptor->DispatchIntegrityObject;
    INTEGRITY_REGION *serviceReg = (INTEGRITY_REGION *)Descriptor->ServiceIntegrityObject;
    QWORD oldDispatchValue, oldServiceValue;
    QWORD newDispatchValue = 0, newServiceValue = 0;
    INTSTATUS status;
    INTRO_ACTION action = introGuestNotAllowed;
    INTRO_ACTION_REASON reason = introReasonUnknown;
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    DWORD offset = 0;

    if (0 == ObjectGva)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    if (NULL == dispatchReg)
    {
        oldDispatchValue = 0;
    }
    else
    {
        oldDispatchValue = *(QWORD *)dispatchReg->OriginalContent;
    }

    if (NULL == serviceReg)
    {
        oldServiceValue = 0;
    }
    else
    {
        oldServiceValue = *(QWORD *)serviceReg->OriginalContent;
    }

    status = IntKernVirtMemFetchWordSize(ObjectGva + DISPATCH_OFFSET, &newDispatchValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemFetchWordSize(ObjectGva + SERVICE_OFFSET, &newServiceValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
        return status;
    }

    if (newDispatchValue == oldDispatchValue && newServiceValue == oldServiceValue)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    // Note: This function is called either on an object relocation or when the object
    // (DispatchAddress/ServiceRoutine) has been modified. On object relocation, if the object
    // was NULL beforehand, then both serviceReg and dispatchReg will be NULL. If the object
    // was valid, or a modification has been detected directly on the object, then both
    // serviceReg and dispatchReg will be valid INTEGRITY_REGION objects.
    if (newDispatchValue == oldDispatchValue && serviceReg != NULL)
    {
        status = IntExceptGetVictimIntegrity(serviceReg, &offset, &victim);
    }
    else if(dispatchReg != NULL)
    {
        status = IntExceptGetVictimIntegrity(dispatchReg, &offset, &victim);
    }
    else
    {
        // If we don't have an integrity region (the object has not been protected beforehand),
        // then we'll need to construct our own victim.
        victim.ZoneType = exceptionZoneIntegrity;
        victim.Object.Type = introObjectTypeInterruptObject;
        victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
        victim.WriteInfo.AccessSize = 2 * gGuest.WordSize;

        status = INT_STATUS_SUCCESS;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting integrity zone: 0x%08x\n", status);
        return status;
    }

    // We'll set the old and new values so that they are in a known order.
    victim.WriteInfo.OldValue[0] = oldDispatchValue;
    victim.WriteInfo.OldValue[1] = oldServiceValue;

    victim.WriteInfo.NewValue[0] = newDispatchValue;
    victim.WriteInfo.NewValue[1] = newServiceValue;

    victim.Integrity.InterruptObjIndex = Descriptor->EntryIndex;
    victim.Integrity.StartVirtualAddress = ObjectGva;

    status = IntExceptGetOriginatorFromModification(&victim, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        return status;
    }

    IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_INTERRUPT_OBJ, &action, &reason))
    {
        IntWinIntObjSendIntegrityAlert(Descriptor, &victim, &originator, action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_INTERRUPT_OBJ, &action);

    *Action = action;
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIntObjHandleObjectModification(
    _Inout_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief  Integrity callback for modifications detected inside protected objects.
///
/// This function will be called whenever a modification is detected over the DispatchAddress
/// or ServiceRoutine fields of the protected KINTERRUPT structure in the InterruptObject array.
/// Note that this function will handle the logic of enforcing the action which was decided by
/// #IntWinIntObjHandleModification.
///
/// @param[in, out] IntegrityRegion The integrity region associated with the protected field.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTOBJ_PROT_DESCRIPTOR *pDescriptor = (INTOBJ_PROT_DESCRIPTOR *)IntegrityRegion->Context;
    INTRO_ACTION action = introGuestAllowed;
    INTSTATUS status;

    status = IntWinIntObjHandleModification(pDescriptor, pDescriptor->ObjectGva, &action);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinIntObjHandleModification failed: 0x%08x\n", status);
        return status;
    }

    if (action == introGuestAllowed)
    {
        IntIntegrityRecalculate(IntegrityRegion);
    }
    else if (action == introGuestNotAllowed)
    {
        IntPauseVcpus();

        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                     IntegrityRegion->Gva,
                                     gGuest.WordSize,
                                     IntegrityRegion->OriginalContent,
                                     IG_CS_RING_0);

        IntResumeVcpus();

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed for gva 0x%016llx: 0x%08x\n",
                  IntegrityRegion->Gva, status);
        }
    }

    return status;
}


static INTSTATUS
IntWinIntObjHandleArrayModification(
    _Inout_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief  Integrity callback for modifications detected inside the array containing the
///         protected objects.
///
/// This function is used for monitoring relocations of objects inside the KPRCB's InterruptObject
/// array. Based on the objects that are relocated, a detection can be made, for example, when a fake
/// object is overwritten in the array. This function will handle the logic of enforcing the decided
/// action from #IntWinIntObjHandleModification, by either protecting the new object, if the relocation
/// is deemed legitimate, or overwriting the old object if not.
///
/// @param[in, out] IntegrityRegion The integrity region associated with the monitorized array.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
/// 
{
    INTSTATUS status;
    INTOBJ_PERPROC_DESCRIPTOR *pDescriptor = (INTOBJ_PERPROC_DESCRIPTOR *)IntegrityRegion->Context;
    QWORD *oldArray = (QWORD *)IntegrityRegion->OriginalContent;
    QWORD *newArray;
    BOOLEAN recalculate = FALSE;
    INTRO_ACTION action = introGuestAllowed;

    status = IntVirtMemMap(IntegrityRegion->Gva, IntegrityRegion->Length, gGuest.Mm.SystemCr3, 0, &newArray);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
        return status;
    }

    for (QWORD i = 0; i < INTERRUPT_OBJECT_COUNT; i++)
    {
        if (oldArray[i] == newArray[i])
        {
            continue;
        }

        status = IntWinIntObjHandleModification(&pDescriptor->IntObjDescriptors[i], newArray[i], &action);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinIntObjHandleModification failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if (action == introGuestAllowed)
        {
            recalculate = TRUE;

            // We need to create a new integrity object for the new object's Dispatch and remove the old one.
            if (NULL != pDescriptor->IntObjDescriptors[i].DispatchIntegrityObject)
            {
                status = IntIntegrityRemoveRegion(pDescriptor->IntObjDescriptors[i].DispatchIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
                    goto cleanup_and_exit;
                }

                pDescriptor->IntObjDescriptors[i].DispatchIntegrityObject = NULL;
            }

            if (newArray[i] != 0 && IS_KERNEL_POINTER_WIN(gGuest.Guest64, newArray[i]))
            {
                status = IntIntegrityAddRegion(newArray[i] + DISPATCH_OFFSET,
                                               gGuest.WordSize,
                                               introObjectTypeInterruptObject,
                                               &pDescriptor->IntObjDescriptors[i],
                                               IntWinIntObjHandleObjectModification,
                                               TRUE,
                                               &pDescriptor->IntObjDescriptors[i].DispatchIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
                    goto cleanup_and_exit;
                }
            }

            // As well as for ServiceRoutine.
            if (NULL != pDescriptor->IntObjDescriptors[i].ServiceIntegrityObject)
            {
                status = IntIntegrityRemoveRegion(pDescriptor->IntObjDescriptors[i].ServiceIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
                    goto cleanup_and_exit;
                }

                pDescriptor->IntObjDescriptors[i].ServiceIntegrityObject = NULL;
            }

            if (newArray[i] != 0 && IS_KERNEL_POINTER_WIN(gGuest.Guest64, newArray[i]))
            {
                status = IntIntegrityAddRegion(newArray[i] + SERVICE_OFFSET,
                                               gGuest.WordSize,
                                               introObjectTypeInterruptObject,
                                               &pDescriptor->IntObjDescriptors[i],
                                               IntWinIntObjHandleObjectModification,
                                               TRUE,
                                               &pDescriptor->IntObjDescriptors[i].ServiceIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
                    goto cleanup_and_exit;
                }
            }
        }
        else if (action == introGuestNotAllowed)
        {
            IntPauseVcpus();

            status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                         IntegrityRegion->Gva + i * gGuest.WordSize,
                                         gGuest.WordSize,
                                         (BYTE *)IntegrityRegion->OriginalContent + i * gGuest.WordSize,
                                         IG_CS_RING_0);

            IntResumeVcpus();

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemSafeWrite failed for gva 0x%016llx: 0x%08x\n",
                      IntegrityRegion->Gva + i * gGuest.WordSize, status);
                goto cleanup_and_exit;
            }
        }
    }

    if (recalculate)
    {
        IntIntegrityRecalculate(IntegrityRegion);
    }

cleanup_and_exit:
    IntVirtMemUnmap(&newArray);

    return status;
}


INTSTATUS
IntWinIntObjProtect(
    void
    )
///
/// @brief  Protects the interrupt objects which are present in the KPRCB's InterruptObject array.
///
/// This will create an integrity region for the array on each CPU's KPRCB, in order to monitor it,
/// through #IntWinIntObjHandleArrayModification, so that the introspection engine can be notified
/// whenever an interrupt object relocation takes place. The DispatchAddress and ServiceRoutine
/// fields are protected in each interrupt object, for which #IntWinIntObjHandleObjectModification
/// will be called whenever a modification is detected.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED         If there is no CPU for which protection can be enforced.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the guest is not 64 bits or if the KPRCB does not have
///                                                 an InterruptObject associated.      
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If there are not enough resources for the protection to be
///                                                 enforced.
///
{
    INTSTATUS status = INT_STATUS_NOT_INITIALIZED;
    QWORD prcb = 0;

    if (!gGuest.Guest64)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == WIN_KM_FIELD(Pcr, PrcbInterruptObject))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    gDescriptors = HpAllocWithTag(gGuest.ActiveCpuCount * sizeof(*gDescriptors), IC_TAG_IOBD);
    if (NULL == gDescriptors)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    for (DWORD i = 0; i < gGuest.ActiveCpuCount; i++)
    {
        if (gGuest.VcpuArray[i].PcrGla == 0)
        {
            status = IntFindKernelPcr(i, &gGuest.VcpuArray[i].PcrGla);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntFindKernelPcr failed: 0x%08x\n", status);
                continue;
            }
        }

        status = IntKernVirtMemFetchWordSize(gGuest.VcpuArray[i].PcrGla + WIN_KM_FIELD(Pcr, Pcrb),
                                             &prcb);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
            continue;
        }

        // First, create an integrity object in order to be notified of modifications on the
        // interrupt object array.
        status = IntIntegrityAddRegion(prcb + WIN_KM_FIELD(Pcr, PrcbInterruptObject),
                                       INTERRUPT_OBJECT_COUNT * gGuest.WordSize,
                                       introObjectTypeInterruptObject,
                                       &gDescriptors[i],
                                       IntWinIntObjHandleArrayModification,
                                       TRUE,
                                       &gDescriptors[i].ObjectIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // For objects in the array that are currently initialized add integrity protection on
        // DispatchAddress and ServiceRoutine.
        for (DWORD intobjidx = 0; intobjidx < INTERRUPT_OBJECT_COUNT; intobjidx++)
        {
            QWORD currentIntObj = 0;
            QWORD addr = prcb + WIN_KM_FIELD(Pcr, PrcbInterruptObject) + (QWORD)intobjidx * gGuest.WordSize;

            gDescriptors[i].IntObjDescriptors[intobjidx].EntryIndex = (BYTE)intobjidx;

            status = IntKernVirtMemFetchWordSize(addr, &currentIntObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
                continue;
            }

            if (0 == currentIntObj || !IS_KERNEL_POINTER_WIN(gGuest.Guest64, currentIntObj))
            {
                continue;
            }

            status = IntIntegrityAddRegion(currentIntObj + DISPATCH_OFFSET,
                                           gGuest.WordSize,
                                           introObjectTypeInterruptObject,
                                           &gDescriptors[i].IntObjDescriptors[intobjidx],
                                           IntWinIntObjHandleObjectModification,
                                           TRUE,
                                           &gDescriptors[i].IntObjDescriptors[intobjidx].DispatchIntegrityObject);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }
           
            status = IntIntegrityAddRegion(currentIntObj + SERVICE_OFFSET,
                                           gGuest.WordSize,
                                           introObjectTypeInterruptObject,
                                           &gDescriptors[i].IntObjDescriptors[intobjidx],
                                           IntWinIntObjHandleObjectModification,
                                           TRUE,
                                           &gDescriptors[i].IntObjDescriptors[intobjidx].ServiceIntegrityObject);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }

            gDescriptors[i].IntObjDescriptors[intobjidx].ObjectGva = currentIntObj;
        }
    }

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntWinIntObjUnprotect();
    }

    return status;
}


INTSTATUS
IntWinIntObjUnprotect(
    void
    )
///
/// @brief  Uninitializes the interrupt objects protection.
///
/// This function will remove all integrity regions associated with protected
/// interrupt object fields, as well as the integrity regions used for monitoring the
/// InterrupObject array.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED     If the protection was not initialized beforehand.
///
{
    INTSTATUS status;

    if (NULL == gDescriptors)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    for (DWORD i = 0; i < gGuest.ActiveCpuCount; i++)
    {
        if (NULL == gDescriptors[i].ObjectIntegrityObject)
        {
            continue;
        }

        status = IntIntegrityRemoveRegion(gDescriptors[i].ObjectIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
        }

        for (DWORD objidx = 0; objidx < INTERRUPT_OBJECT_COUNT; objidx++)
        {
            if (gDescriptors[i].IntObjDescriptors[objidx].DispatchIntegrityObject != NULL)
            {
                status = IntIntegrityRemoveRegion(gDescriptors[i].IntObjDescriptors[objidx].DispatchIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
                }

                gDescriptors[i].IntObjDescriptors[objidx].DispatchIntegrityObject = NULL;
            }

            if (gDescriptors[i].IntObjDescriptors[objidx].ServiceIntegrityObject != NULL)
            {
                status = IntIntegrityRemoveRegion(gDescriptors[i].IntObjDescriptors[objidx].ServiceIntegrityObject);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
                }

                gDescriptors[i].IntObjDescriptors[objidx].ServiceIntegrityObject = NULL;
            }
        }
    }

    HpFreeAndNullWithTag(&gDescriptors, IC_TAG_IOBD);

    return INT_STATUS_SUCCESS;
}
