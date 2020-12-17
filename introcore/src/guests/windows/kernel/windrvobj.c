/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windrvobj.h"
#include "windrv_protected.h"
#include "alerts.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"
#include "winpe.h"

/// @brief  List of all the loaded Windows driver objects.
static LIST_HEAD gWinDriverObjects = LIST_HEAD_INIT(gWinDriverObjects);

static INTSTATUS
IntWinDrvObjUnprotectFastIoDispatch(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    );

static INTSTATUS
IntWinDrvObjProtectFastIoDispatch(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    );


BOOLEAN
IntWinDrvObjIsValidDriverObject(
    _In_ QWORD DriverObjectAddress
    )
///
/// @brief      Checks if a guest memory area contains a valid _DRIVER_OBJECT structure.
///
/// The check is based on invariants:
///     - the object must be in the kernel's address space
///     - the object must be present in memory
///     - the Type field must be #DRIVER_OBJECT_TYPE
///     - the DriverStart should be present, not be accessible from user mode, and be cacheable
///     - the module that owns the driver must have a valid MZPE header
///     - the DriverSize from the object must match the one from the module
///     - the entry point from the module must match the one from the driver object
///
/// The #DRIVER_OBJECT64 definition is used for the checks on 64-bit guests; the #DRIVER_OBJECT32 definition is used
/// for 32-bit guests.
///
/// @param[in]  DriverObjectAddress The guest virtual address to check.
///
/// @returns    True if DriverObjectAddress points to a valid driver object; False if it does not.
///
{
    INTSTATUS status;
    PBYTE pObject, pModule;
    BOOLEAN valid;
    VA_TRANSLATION translation;

    valid = FALSE;

    pObject = NULL;
    pModule = NULL;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, DriverObjectAddress))
    {
        return FALSE;
    }

    status = IntVirtMemMap(DriverObjectAddress,
                           WIN_KM_FIELD(DrvObj, Size),
                           gGuest.Mm.SystemCr3,
                           0,
                           &pObject);
    if (!INT_SUCCESS(status))
    {
        return FALSE;
    }

    if (gGuest.Guest64)
    {
        DRIVER_OBJECT64 const *pDrvObj = (DRIVER_OBJECT64 *)pObject;
        INTRO_PE_INFO peInfo = {0};

        if (pDrvObj->Type != DRIVER_OBJECT_TYPE)
        {
            goto cleanup_and_exit;
        }

        if (pDrvObj->Size != WIN_KM_FIELD(DrvObj, Size))
        {
            goto cleanup_and_exit;
        }

        if (pDrvObj->DriverStart % PAGE_SIZE != 0)
        {
            goto cleanup_and_exit;
        }

        // Try to translate the driver start, in order to see if it leads to a valid address.
        status = IntTranslateVirtualAddressEx(pDrvObj->DriverStart, gGuest.Mm.SystemCr3, TRFLG_NONE, &translation);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        if (!(translation.Flags & PT_P))
        {
            goto cleanup_and_exit;
        }

        if (translation.Flags & PT_US)
        {
            goto cleanup_and_exit;
        }

        if (translation.Flags & PT_PCD)
        {
            // We shouldn't touch non-cacheable pages.
            goto cleanup_and_exit;
        }

        status = IntPhysMemMap(translation.PhysicalAddress, PAGE_SIZE, 0, &pModule);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        status = IntPeValidateHeader(pDrvObj->DriverStart, pModule, PAGE_SIZE, &peInfo, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if (peInfo.SizeOfImage != pDrvObj->DriverSize)
        {
            goto cleanup_and_exit;
        }

        if (peInfo.EntryPoint != (pDrvObj->DriverInit - pDrvObj->DriverStart))
        {
            goto cleanup_and_exit;
        }
    }
    else
    {
        DRIVER_OBJECT32 const *pDrvObj = (DRIVER_OBJECT32 *)pObject;
        INTRO_PE_INFO peInfo = {0};

        if (pDrvObj->Type != DRIVER_OBJECT_TYPE)
        {
            goto cleanup_and_exit;
        }

        if (pDrvObj->Size != WIN_KM_FIELD(DrvObj, Size))
        {
            goto cleanup_and_exit;
        }

        if (pDrvObj->DriverStart % PAGE_SIZE != 0)
        {
            goto cleanup_and_exit;
        }

        // Try to translate the driver start, in order to see if it leads to a valid address.
        status = IntTranslateVirtualAddressEx(pDrvObj->DriverStart, gGuest.Mm.SystemCr3, TRFLG_NONE, &translation);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        if (!(translation.Flags & PT_P))
        {
            goto cleanup_and_exit;
        }

        if (translation.Flags & PT_US)
        {
            goto cleanup_and_exit;
        }

        if (translation.Flags & PT_PCD)
        {
            // We shouldn't touch non-cacheable pages.
            goto cleanup_and_exit;
        }

        status = IntPhysMemMap(translation.PhysicalAddress, PAGE_SIZE, 0, &pModule);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        status = IntPeValidateHeader(pDrvObj->DriverStart, pModule, PAGE_SIZE, &peInfo, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if (peInfo.SizeOfImage != pDrvObj->DriverSize)
        {
            goto cleanup_and_exit;
        }

        if (peInfo.EntryPoint != (pDrvObj->DriverInit - pDrvObj->DriverStart))
        {
            goto cleanup_and_exit;
        }
    }

    valid = TRUE;

cleanup_and_exit:
    if (NULL != pObject)
    {
        IntVirtMemUnmap(&pObject);
    }

    if (NULL != pModule)
    {
        IntPhysMemUnmap(&pModule);
    }

    return valid;
}


INTSTATUS
IntWinDrvObjCreateFromAddress(
    _In_ QWORD GuestAddress,
    _In_ BOOLEAN StaticDetected,
    _Out_opt_ PWIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief      Creates a new driver object.
///
/// If a driver object for GuestAddress is already known this function does nothing. This function assumes that
/// GuestAddress points to a valid driver object. #IntWinDrvObjIsValidDriverObject should be used to validate that
/// this is true before calling this function. The driver will be inserted in the #gWinDriverObjects list and will
/// be protected (alongside its fast IO dispatch structure), if necessary.
///
/// @param[in]  GuestAddress    Guest virtual address at which the _DRIVER_OBJECT structure is found.
/// @param[in]  StaticDetected  True if the driver object was detected after it was created, through a memory scan.
///                             False if it was detected when it was created.
/// @param[out] DriverObject    On success, will contain a pointer to the created #WIN_DRIVER_OBJECT. If a driver
///                             object already exists for GuestAddress it will point to that driver object. May be NULL.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if a driver object for GuestAddress already exists.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available.
///
{
    PWIN_DRIVER_OBJECT pDrvObj;
    KERNEL_DRIVER *pKm;
    INTSTATUS status;
    DWORD driverNameLen;
    QWORD driverNameAddress;

    driverNameAddress = 0;
    driverNameLen = 0;

    pDrvObj = IntWinDrvObjFindByDrvObj(GuestAddress);
    if (pDrvObj)
    {
        WARNING("[WARNING] Driver object at 0x%016llx is already present as \"%s\", will ignore\n",
                GuestAddress, utf16_for_log(pDrvObj->Name));
        if (NULL != DriverObject)
        {
            *DriverObject = pDrvObj;
        }
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pDrvObj = HpAllocWithTag(sizeof(*pDrvObj), IC_TAG_DOBJ);
    if (NULL == pDrvObj)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Start filling in driver object info.
    pDrvObj->DriverObjectGva = GuestAddress;
    pDrvObj->Aligned = !StaticDetected;

    status = IntTranslateVirtualAddress(GuestAddress, gGuest.Mm.SystemCr3, &pDrvObj->DriverObjectGpa);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed translating GVA 0x%016llx: 0x%08x\n", GuestAddress, status);
        pDrvObj->DriverObjectGpa = 0;
    }

    // Read the driver name length
    if (!gGuest.Guest64)
    {
        status = IntKernVirtMemFetchDword(GuestAddress + OFFSET_OF(DRIVER_OBJECT32,
                                                                   DriverName.Length), &driverNameLen);
    }
    else
    {
        status = IntKernVirtMemFetchDword(GuestAddress + OFFSET_OF(DRIVER_OBJECT64,
                                                                   DriverName.Length), &driverNameLen);
    }
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    // Read the driver name address
    if (!gGuest.Guest64)
    {
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT32,
                                                                      DriverName.Buffer), &driverNameAddress);
    }
    else
    {
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT64,
                                                                      DriverName.Buffer), &driverNameAddress);
    }
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    driverNameLen = (driverNameLen & 0xFFFF);

    // Validate driver name length.
    if ((driverNameLen < 2) || (driverNameLen >= 256))
    {
        // To small or to long, we ignore it.
        goto cleanup_and_exit;
    }

    // driverNameLen + 2 OK - we just checked above to see if its below 256.
    pDrvObj->Name = HpAllocWithTag(driverNameLen + 2ull, IC_TAG_DRNU);
    if (NULL == pDrvObj->Name)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    // Read the driver name
    status = IntKernVirtMemRead(driverNameAddress, driverNameLen, pDrvObj->Name, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading the driver name: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pDrvObj->NameLen = driverNameLen / 2;

    // Lowercase the name
    strlower_utf16(pDrvObj->Name, pDrvObj->NameLen);

    // Helps us on exceptions
    pDrvObj->NameHash = Crc32Wstring(pDrvObj->Name, INITIAL_CRC_VALUE);

    // Read the owner driver
    if (!gGuest.Guest64)
    {
        pDrvObj->Owner = 0;
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT32, DriverStart), &pDrvObj->Owner);
    }
    else
    {
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT64, DriverStart), &pDrvObj->Owner);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading the driver start: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Now get the pointer to the fast I/O dispatch table, if any.
    if (!gGuest.Guest64)
    {
        pDrvObj->FastIOTableAddress = 0;
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT32, FastIoDispatch),
                                             &pDrvObj->FastIOTableAddress);
    }
    else
    {
        status = IntKernVirtMemFetchWordSize(GuestAddress + OFFSET_OF(DRIVER_OBJECT64, FastIoDispatch),
                                             &pDrvObj->FastIOTableAddress);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
    }

    pKm = IntDriverFindByAddress(pDrvObj->Owner);
    if (NULL != pKm)
    {
        pKm->Win.DriverObject = pDrvObj;
    }

    InsertTailList(&gWinDriverObjects, &pDrvObj->Link);

    // Once the object is allocated and added to the list, we can activate protection on it.
    if (IntWinDrvObjIsProtected(pDrvObj))
    {
        // Protect the driver object, together with the fast I/O dispatch table.
        status = IntWinDrvObjProtect(pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHookDriverObject failed: 0x%08x\n", status);
        }
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntWinDrvObjRemove(pDrvObj);
    }

    if (NULL != DriverObject)
    {
        *DriverObject = pDrvObj;
    }

    return status;
}


PWIN_DRIVER_OBJECT
IntWinDrvObjFindByDrvObj(
    _In_ QWORD Gva
    )
///
/// @brief      Finds a driver object in the #gWinDriverObjects list by its guest virtual address.
///
/// @param[in]  Gva     Guest virtual address to search by.
///
/// @returns    A pointer to the #WIN_DRIVER_OBJECT that matches Gva, or NULL if no match exists.
///
{
    LIST_ENTRY *list = gWinDriverObjects.Flink;
    while (list != &gWinDriverObjects)
    {
        PWIN_DRIVER_OBJECT pDrvObj = CONTAINING_RECORD(list, WIN_DRIVER_OBJECT, Link);

        if (pDrvObj->DriverObjectGva == Gva)
        {
            return pDrvObj;
        }

        list = list->Flink;
    }

    return NULL;
}


PWIN_DRIVER_OBJECT
IntWinDrvObjFindByOwnerAddress(
    _In_ QWORD Owner
    )
///
/// @brief      Finds a driver object in the #gWinDriverObjects list by the base of the kernel module that owns it.
///
/// @param[in]  Owner   Guest virtual address to search by.
///
/// @returns    A pointer to the #WIN_DRIVER_OBJECT that matches Gva, or NULL if no match exists.
///
{
    LIST_ENTRY *list = gWinDriverObjects.Flink;
    while (list != &gWinDriverObjects)
    {
        PWIN_DRIVER_OBJECT pDrvObj = CONTAINING_RECORD(list, WIN_DRIVER_OBJECT, Link);

        if (pDrvObj->Owner == Owner)
        {
            return pDrvObj;
        }

        list = list->Flink;
    }

    return NULL;
}


static INTSTATUS
IntWinDrvObjSendEptAlert(
    _In_ EXCEPTION_VICTIM_ZONE const *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR const *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      Sends an #introEventEptViolation alert for a protected driver object.
///
/// @param[in]  Victim      The victim information, as obtained from the exception mechanism.
/// @param[in]  Originator  Originator information, as obtained from the exception mechanism.
/// @param[in]  Action      The action that was taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    PEVENT_EPT_VIOLATION pEptViol;
    IG_ARCH_REGS const *regs;

    regs = &gVcpu->Regs;

    pEptViol = &gAlert.Ept;
    memzero(pEptViol, sizeof(*pEptViol));

    pEptViol->Header.Action = Action;
    pEptViol->Header.Reason = Reason;
    pEptViol->Header.MitreID = idRootkit;

    pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_DRVOBJ, Reason);

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(Originator, pEptViol);
    IntAlertEptFillFromVictimZone(Victim, pEptViol);

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
IntWinDrvObjSendIntegrityAlert(
    _In_ EXCEPTION_VICTIM_ZONE const *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR const *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      Sends an #introEventIntegrityViolation alert for a protected driver object.
///
/// @param[in]  Victim      The victim information, as obtained from the exception mechanism.
/// @param[in]  Originator  Originator information, as obtained from the exception mechanism.
/// @param[in]  Action      The action that was taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
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

    // we can't know from what CPU the write was, but we know where the integrity check failed
    pIntViol->Header.CpuContext.Valid = FALSE;

    pIntViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_DRVOBJ, Reason);
    pIntViol->Header.Flags |= ALERT_FLAG_ASYNC;

    pIntViol->Header.Action = Action;
    pIntViol->Header.Reason = Reason;
    pIntViol->Header.MitreID = idRootkit;

    memcpy(pIntViol->Victim.Name, VICTIM_DRIVER_OBJECT, sizeof(VICTIM_DRIVER_OBJECT));

    IntAlertFillWriteInfo(Victim, &pIntViol->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &pIntViol->Originator.Module);

    IntAlertFillDriverObject((PWIN_DRIVER_OBJECT)Victim->Object.DriverObject, &pIntViol->Victim.DriverObject);

    IntAlertFillCpuContext(FALSE, &pIntViol->Header.CpuContext);

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
IntWinDrvObjHandleWrite(
    _Inout_ WIN_DRIVER_OBJECT *Context,
    _In_ HOOK_GPA const *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles writes done over a protected driver object.
///
/// This is the EPT write callback set by #IntWinDrvObjProtect. If the write relocates the fast IO dispatch, this
/// will send an #introEventEptViolation with the object type #introObjectTypeFastIoDispatch. Otherwise, the type
/// will be #introObjectTypeDriverObject.
/// If the guest physical address of the driver object has been changed, the #WIN_DRIVER_OBJECT.DriverObjectGpa field
/// will be updated here. This will also update the #WIN_KERNEL_DRIVER structure of the owner module with a pointer
/// to the driver object, the link has not been previously established. If the old fast IO dispatch pointer was 0,
/// the newly written one is considered to be the good one and it will be protected and the write will be allowed.
///
/// @param[in]  Context     Context passed by #IntWinDrvObjProtect when the hook was set. This will be the protected
///                         driver object.
/// @param[in]  Hook        The GPA hook object for this hook.
/// @param[in]  Address     The accessed guest physical address.
/// @param[out] Action      The action that must be taken.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the fast IO dispatch is relocated and the new value is non zero and not
///             inside the kernel virtual address space.
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;

    WIN_DRIVER_OBJECT *pDrvObj = Context;
    HOOK_GVA const *pGva = Hook->Header.ParentHook;
    QWORD gva = pGva->GvaPage + (Address & PAGE_OFFSET);
    OPERAND_VALUE writtenValue = {0};

    BOOLEAN exitAfterInformation = FALSE;
    BOOLEAN fastIoPtrWritten = FALSE;
    BOOLEAN fastIoWrite = FALSE;
    BOOLEAN fastIoUpdated = FALSE;
    QWORD gpa;
    KERNEL_DRIVER *pKm;

    INTRO_ACTION_REASON reason = introReasonUnknown;

    IG_ARCH_REGS *regs = &gVcpu->Regs;
    INSTRUX *pInstrux = &gVcpu->Instruction;

    // Check to  see if the Fast I/O dispatch pointer is being written. If it is, hook the new
    // Fast I/O dispatch table.
    if (gGuest.Guest64)
    {
        if ((gva >= pDrvObj->DriverObjectGva + OFFSET_OF(DRIVER_OBJECT64, FastIoDispatch)) &&
            (gva < pDrvObj->DriverObjectGva + OFFSET_OF(DRIVER_OBJECT64, FastIoDispatch) + 8))
        {
            fastIoPtrWritten = TRUE;
        }
    }
    else
    {
        if ((gva >= pDrvObj->DriverObjectGva + OFFSET_OF(DRIVER_OBJECT32, FastIoDispatch)) &&
            (gva < pDrvObj->DriverObjectGva + OFFSET_OF(DRIVER_OBJECT32, FastIoDispatch) + 4))
        {
            fastIoPtrWritten = TRUE;
        }
    }

    if (fastIoPtrWritten)
    {
        status = IntDecGetWrittenValueFromInstruction(pInstrux, regs, NULL, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecGetWrittenValueFromInstruction failed: 0x%08x\n", status);

            IntDbgEnterDebugger();

            goto cleanup_and_exit;
        }

        if ((0 != writtenValue.Value.QwordValues[0]) &&
            !IS_KERNEL_POINTER_WIN(gGuest.Guest64, writtenValue.Value.QwordValues[0]))
        {
            ERROR("[ERROR] [DRVOBJ] Fast I/O dispatch table of driver object '%s' not in kernel: 0x%016llx\n",
                  utf16_for_log(pDrvObj->Name), writtenValue.Value.QwordValues[0]);

            status = INT_STATUS_NOT_SUPPORTED;

            goto cleanup_and_exit;
        }

        if (pDrvObj->FastIOTableAddress != 0)
        {
            goto _block_fastio_reloc;
        }

        TRACE("[DRVOBJ] Fast I/O dispatch table of driver object '%s' has been written: 0x%016llx\n",
              utf16_for_log(pDrvObj->Name), writtenValue.Value.QwordValues[0]);

        status = IntWinDrvObjUnprotectFastIoDispatch(pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed: 0x%08x\n", status);
        }

        // Update new entry.
        pDrvObj->FastIOTableAddress = writtenValue.Value.QwordValues[0];

        if (0 != pDrvObj->FastIOTableAddress)
        {
            status = IntWinDrvObjProtectFastIoDispatch(pDrvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjHookFastIODispatch failed: 0x%08x\n", status);
            }
        }

        *Action = introGuestAllowed;

        status = INT_STATUS_SUCCESS;

        fastIoUpdated = TRUE;

        goto cleanup_and_exit;
    }

_block_fastio_reloc:
    STATS_ENTER(statsExceptionsKern);

    status = IntTranslateVirtualAddress(pDrvObj->DriverObjectGva, gGuest.Mm.SystemCr3, &gpa);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntTranslateVirtualAddress failed: 0x%08x\n", status);
    }
    else if (gpa != pDrvObj->DriverObjectGpa)
    {
        WARNING("[WARNING] The driver object Gpa 0x%016llx is different from actual Gpa 0x%016llx!\n",
                pDrvObj->DriverObjectGpa, gpa);
        pDrvObj->DriverObjectGpa = gpa;
    }

    pKm = IntDriverFindByAddress(pDrvObj->Owner);
    if (NULL != pKm && NULL == pKm->Win.DriverObject)
    {
        pKm->Win.DriverObject = pDrvObj;
    }

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;
    exitAfterInformation = FALSE;

    if (pDrvObj->FastIOTableAddress &&
        gva >= pDrvObj->FastIOTableAddress &&
        gva < pDrvObj->FastIOTableAddress + WIN_KM_FIELD(DrvObj, FiodispSize))
    {
        fastIoWrite = TRUE;
    }

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (INT_STATUS_EXCEPTION_BLOCK == status)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
    }

    status = IntExceptGetVictimEpt(pDrvObj,
                                   Address,
                                   gva,
                                   fastIoWrite ? introObjectTypeFastIoDispatch : introObjectTypeDriverObject,
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
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_DRVOBJ, Action, &reason))
    {
        IntWinDrvObjSendEptAlert(&victim, &originator, *Action, reason);
    }

cleanup_and_exit:
    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_DRVOBJ, Action);

    if (*Action == introGuestAllowed &&
        !fastIoUpdated &&
        fastIoPtrWritten)
    {
        status = IntWinDrvObjUnprotectFastIoDispatch(pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed with status: 0x%08x\n", status);
            return status;
        }

        pDrvObj->FastIOTableAddress = gGuest.Guest64 ? writtenValue.Value.QwordValues[0] :
            writtenValue.Value.DwordValues[0];

        if (pDrvObj->FastIOTableAddress != 0)
        {
            status = IntWinDrvObjProtectFastIoDispatch(pDrvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed with status: 0x%08x\n", status);
                return status;
            }
        }
    }

    return status;
}


static INTSTATUS
IntWinDrvObjHandleModification(
    _Inout_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief      Handles writes done over a protected driver object.
///
/// This is the integrity write callback set by #IntWinDrvObjProtect or by #IntWinDrvObjProtectFastIoDispatch.
/// If the fast IO dispatch pointer is changed by fltmgr, the write is allowed.
///
/// @param[in, out] IntegrityRegion The integrity region used to protect the driver object.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
#define NAMEHASH_FLTMGR 0x4283398b
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTSTATUS status;
    DWORD offset;
    BOOLEAN recalculate = FALSE;

    if (IntegrityRegion->Type != introObjectTypeDriverObject &&
        IntegrityRegion->Type != introObjectTypeFastIoDispatch)
    {
        ERROR("[ERROR] Invalid integrity region type: %d\n", IntegrityRegion->Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    STATS_ENTER(statsExceptionsKern);

    offset = 0;
    status = INT_STATUS_SUCCESS;

    while (offset < IntegrityRegion->Length)
    {
        INTRO_ACTION action = introGuestNotAllowed;
        INTRO_ACTION_REASON reason = introReasonUnknown;
        const QWORD fioDispOffset = WIN_KM_FIELD(DrvObj, Fiodisp);

        memzero(&victim, sizeof(victim));
        memzero(&originator, sizeof(originator));

        status = IntExceptGetVictimIntegrity(IntegrityRegion, &offset, &victim);
        if (status == INT_STATUS_NOT_FOUND)
        {
            // We are done with the modifications, so exit
            status = INT_STATUS_SUCCESS;
            break;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting integrity zone: 0x%08x\n", status);
            break;
        }

        status = IntExceptGetOriginatorFromModification(&victim, &originator);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            // In case of something that can't be excepted (like the size field, etc.)
            action = introGuestAllowed;
            goto _do_action;
        }
        else if (status == INT_STATUS_EXCEPTION_BLOCK)
        {
            // Or something that it's wrong (like the size filed being too big, etc.)
            status = INT_STATUS_SUCCESS;
            reason = introReasonInternalError;

            IntExceptKernelLogInformation(&victim, &originator, action, reason);

            goto _do_action;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
            break;
        }

        if (((gGuest.Guest64 &&
            victim.Integrity.Offset + fioDispOffset == OFFSET_OF(DRIVER_OBJECT64, DriverUnload)) ||
            (!gGuest.Guest64 &&
            victim.Integrity.Offset + fioDispOffset == OFFSET_OF(DRIVER_OBJECT32, DriverUnload))) &&
            (originator.Original.NameHash == NAMEHASH_FLTMGR))
        {
            action = introGuestAllowed;
            goto _do_action;
        }

        IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

_do_action:
        if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_DRVOBJ, &action, &reason))
        {
            IntWinDrvObjSendIntegrityAlert(&victim, &originator, action, reason);
        }

        IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_DRVOBJ, &action);

        if (action == introGuestAllowed)
        {
            recalculate = TRUE;

            if (IntegrityRegion->Type == introObjectTypeDriverObject && victim.Integrity.Offset == 0)
            {
                WIN_DRIVER_OBJECT *pDrvObj = victim.Object.DriverObject;

                status = IntWinDrvObjUnprotectFastIoDispatch(pDrvObj);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed with status: 0x%08x\n", status);
                    goto _cleanup_and_exit;
                }

                if (gGuest.Guest64)
                {
                    pDrvObj->FastIOTableAddress = victim.WriteInfo.NewValue[0];
                }
                else
                {
                    pDrvObj->FastIOTableAddress = (DWORD)(victim.WriteInfo.NewValue[0]);
                }

                if (pDrvObj->FastIOTableAddress != 0)
                {
                    status = IntWinDrvObjProtectFastIoDispatch(pDrvObj);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed with status: 0x%08x\n", status);
                        goto _cleanup_and_exit;
                    }
                }
            }
        }
        else if (action == introGuestNotAllowed)
        {
            QWORD original = 0;

            if (gGuest.Guest64)
            {
                original = *(QWORD *)((PBYTE)IntegrityRegion->OriginalContent + victim.Integrity.Offset);
            }
            else
            {
                original = *(DWORD *)((PBYTE)IntegrityRegion->OriginalContent + victim.Integrity.Offset);
            }

            IntPauseVcpus();

            // No need to use IntVirtMemSafeWrite, as this is a protected region.
            status = IntKernVirtMemWrite(IntegrityRegion->Gva + victim.Integrity.Offset, gGuest.WordSize, &original);

            IntResumeVcpus();

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemWrite failed for gva 0x%016llx: 0x%08x\n",
                      IntegrityRegion->Gva + victim.Integrity.Offset, status);
                goto _cleanup_and_exit;
            }
        }
    }

    if (recalculate)
    {
        IntIntegrityRecalculate(IntegrityRegion);
    }

_cleanup_and_exit:
    STATS_EXIT(statsExceptionsKern);

    return status;

#undef NAMEHASH_FLTMGR
}


static INTSTATUS
IntWinDrvObjUnprotectFastIoDispatch(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief      Deactivates the protection for the fast IO dispatch structure of a driver object.
///
/// @param[in]  DriverObject    The driver object for which to deactivate the fast IO dispatch protection.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the fast IO dispatch is not protected.
///
{
    INTSTATUS status;

    if (!DriverObject->FiodispProtected)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DRVOBJ] Removing protection on Fast I/OP dispatch on driver object '%s' at %llx...\n",
          utf16_for_log(DriverObject->Name), DriverObject->FastIOTableAddress);

    if (DriverObject->FiodispIntegrityObject != NULL)
    {
        status = IntIntegrityRemoveRegion(DriverObject->FiodispIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed removing the integrity region from structure at address 0x%016llx: 0x%08x\n",
                  DriverObject->FastIOTableAddress, status);
        }
        DriverObject->FiodispIntegrityObject = NULL;
    }

    DriverObject->FiodispProtected = FALSE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDrvObjProtectFastIoDispatch(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief      Deactivates the protection for the fast IO dispatch structure of a driver object.
///
/// The fast IO dispatch structure is always protected with the integrity mechanism, even if we used an EPT hook
/// for the driver object itself. This is done because hooking the page with the fast IO dispatch may generate a lot
/// of unrelated EPT violations.
///
/// @param[in]  DriverObject    The driver object for which to activate the fast IO dispatch protection.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the fast IO dispatch address is 0.
///
{
    INTSTATUS status;

    if (0 == DriverObject->FastIOTableAddress)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DRVOBJ] Adding protection on Fast I/O dispatch for driver object '%s' at 0x%016llx (integrity)\n",
          utf16_for_log(DriverObject->Name), DriverObject->FastIOTableAddress);

    status = IntIntegrityAddRegion(DriverObject->FastIOTableAddress,
                                   WIN_KM_FIELD(DrvObj, FiodispSize),
                                   introObjectTypeFastIoDispatch,
                                   DriverObject,
                                   IntWinDrvObjHandleModification,
                                   TRUE,
                                   &DriverObject->FiodispIntegrityObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
        return status;
    }

    DriverObject->FiodispProtected = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvObjUnprotect(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief          Deactivates protection for a driver object and its fast IO dispatch structure.
///
/// @param[in, out] DriverObject    The object for which the protection will be removed.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_INVALID_PARAMETER_1 if DriverObject is NULL.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT if the driver object is not protected. There is no need to also
///                 check the fast IO dispatch, as it can not be protected if the driver object itself is not
///                 protected.
///
{
    INTSTATUS status;

    if (NULL == DriverObject)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!DriverObject->DrvobjProtected)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DRVOBJ] Removing protection on driver object '%s' at %llx...\n",
          utf16_for_log(DriverObject->Name), DriverObject->DriverObjectGva);

    status = IntWinDrvObjUnprotectFastIoDispatch(DriverObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinDrvObjFiodispUnHook failed: 0x%08x\n", status);
    }

    if (DriverObject->DrvobjIntegrityObject != NULL)
    {
        status = IntIntegrityRemoveRegion(DriverObject->DrvobjIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed removing the integrity region from structure at address 0x%016llx: 0x%08x\n",
                  DriverObject->DriverObjectGva, status);
        }
        DriverObject->DrvobjIntegrityObject = NULL;
    }

    if (DriverObject->DrvobjHookObject != NULL)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&DriverObject->DrvobjHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed removing the hook from structure at address 0x%016llx: 0x%08x\n",
                  DriverObject->FastIOTableAddress, status);
        }
    }

    DriverObject->DrvobjProtected = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvObjProtect(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief          Protects a driver object and its fast IO dispatch table, if one exists.
///
/// This will set an EPT or an integrity hook for the driver object and an integrity hook for the fast IO dispatch
/// table.
///
/// @param[in, out] DriverObject    Driver object to be protected.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_INVALID_PARAMETER_1 if DriverObject is NULL.
///
{
    INTSTATUS status;

    if (DriverObject == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntWinDrvObjProtectFastIoDispatch(DriverObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinHookFastIODispatch failed: 0x%08x\n", status);
    }

    // If the protection is already activated, then we can hook the driver object since the pool size is a whole page
    if (!DriverObject->Aligned)
    {
        TRACE("[DRVOBJ] Adding protection on driver object '%s' at %llx (integrity)...\n",
              utf16_for_log(DriverObject->Name), DriverObject->DriverObjectGva);

        status = IntIntegrityAddRegion(DriverObject->DriverObjectGva + WIN_KM_FIELD(DrvObj, Fiodisp),
                                       WIN_KM_FIELD(DrvObj, Size) - WIN_KM_FIELD(DrvObj, Fiodisp),
                                       introObjectTypeDriverObject,
                                       DriverObject,
                                       IntWinDrvObjHandleModification,
                                       TRUE,
                                       &DriverObject->DrvobjIntegrityObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        TRACE("[DRVOBJ] Adding protection on driver object '%s' at %llx (ept)...\n",
              utf16_for_log(DriverObject->Name), DriverObject->DriverObjectGva);

        status = IntHookObjectCreate(introObjectTypeDriverObject, 0, &DriverObject->DrvobjHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }

        status = IntHookObjectHookRegion(DriverObject->DrvobjHookObject,
                                         0,
                                         DriverObject->DriverObjectGva + WIN_KM_FIELD(DrvObj, Fiodisp),
                                         WIN_KM_FIELD(DrvObj, Size) - WIN_KM_FIELD(DrvObj, Fiodisp),
                                         IG_EPT_HOOK_WRITE,
                                         IntWinDrvObjHandleWrite,
                                         DriverObject,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            return status;
        }
    }

    DriverObject->DrvobjProtected = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvObjRemoveFromAddress(
    _In_ QWORD DriverObjectAddress
    )
///
/// @brief      Frees and removes protection for a driver object by its address.
///
/// @param[in]  DriverObjectAddress     Guest virtual address of the driver object.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_FOUND if no driver object is found.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;
    BOOLEAN bFound;
    QWORD drvObjGpa;

    bFound = FALSE;

    status = IntTranslateVirtualAddress(DriverObjectAddress, gGuest.Mm.SystemCr3, &drvObjGpa);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddress failed for GVA 0x%016llx: 0x%08x\n", DriverObjectAddress, status);
        drvObjGpa = 0;
    }

    list = gWinDriverObjects.Flink;
    while (list != &gWinDriverObjects)
    {
        PWIN_DRIVER_OBJECT drvObj = CONTAINING_RECORD(list, WIN_DRIVER_OBJECT, Link);
        list = list->Flink;

        // Search the driver corresponding to this pool
        if ((drvObjGpa != 0 && drvObjGpa + WIN_KM_FIELD(DrvObj, AllocationGap) == drvObj->DriverObjectGpa) ||
            (DriverObjectAddress + WIN_KM_FIELD(DrvObj, AllocationGap) == drvObj->DriverObjectGva))

        {
            TRACE("[DRVOBJ] Removing driver object at 0x%016llx\n", drvObj->DriverObjectGva);

            RemoveEntryList(&drvObj->Link);

            status = IntWinDrvObjRemove(drvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjRemoveDriverObject failed: 0x%08x\n", status);
            }

            bFound = TRUE;

            // There can be more GVAs pointing to this gpa, so don't break!
        }
        else if (DriverObjectAddress == drvObj->FastIOTableAddress)
        {
            TRACE("[DRVOBJ] Removing Fast I/O dispatch at 0x%016llx\n", drvObj->FastIOTableAddress);

            status = IntWinDrvObjUnprotectFastIoDispatch(drvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjUnprotectFastIoDispatch failed: 0x%08x\n", status);
            }

            bFound = TRUE;

            // If we have multiple driver objects, remove all the hooks!
        }
    }

    if (!bFound)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinDrvObjFreeDriverObject(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief      Frees a driver object.
///
/// This will free the driver object itself and the memory allocated for its name.
///
/// @param[in]  DriverObject    Object to free. The pointer will no longer be valid after this function returns.
///
{
    if (NULL != DriverObject->Name)
    {
        HpFreeAndNullWithTag(&DriverObject->Name, IC_TAG_DRNU);
    }

    HpFreeAndNullWithTag(&DriverObject, IC_TAG_DOBJ);
}


INTSTATUS
IntWinDrvObjRemove(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    )
///
/// @brief      Removes a driver object and updates its owner module.
///
/// If there is a #KERNEL_DRIVER that owns this driver object, it's DriverObject field will be set to NULL.
///
/// @param[in]  DriverObject    Object to remove.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if DriverObject is NULL.
///
{
    KERNEL_DRIVER *pKmDriver;
    INTSTATUS status;

    if (NULL == DriverObject)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pKmDriver = IntDriverFindByAddress(DriverObject->Owner);
    if (NULL != pKmDriver)
    {
        pKmDriver->Win.DriverObject = NULL;
    }

    status = IntWinDrvObjUnprotect(DriverObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinDrvObjUnprotect failed: 0x%08x\n", status);
    }

    IntWinDrvObjFreeDriverObject(DriverObject);

    return status;
}


INTSTATUS
IntWinDrvObjUpdateProtection(
    void
    )
///
/// @brief      Updates the protection for all the driver objects in the #gWinDriverObjects list.
///
/// Based on new core options (@ref group_options) protection will be activated or deactivated.
///
{
    INTSTATUS status;

    TRACE("[DRVOBJ] Updating driver objects protections...\n");

    for (LIST_ENTRY *list = gWinDriverObjects.Flink; list != &gWinDriverObjects; list = list->Flink)
    {
        PWIN_DRIVER_OBJECT pDrvObj = CONTAINING_RECORD(list, WIN_DRIVER_OBJECT, Link);
        const PROTECTED_MODULE_INFO *pProtInfo;

        pProtInfo = IntWinDrvObjIsProtected(pDrvObj);
        if (!pDrvObj->DrvobjProtected && (NULL != pProtInfo))
        {
            status = IntWinDrvObjProtect(pDrvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjProtect failed for '%s': 0x%08x\n",
                      utf16_for_log(pDrvObj->Name), status);
            }
        }
        else if (pDrvObj->DrvobjProtected && (NULL == pProtInfo))
        {
            status = IntWinDrvObjUnprotect(pDrvObj);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvObjUnprotect failed for '%s': 0x%08x\n",
                      utf16_for_log(pDrvObj->Name), status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvObjUninit(
    void
    )
///
/// @brief      Removes all the driver objects in the #gWinDriverObjects.
///
/// This will free any resources held by the driver objects and will remove their protection.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;

    LIST_ENTRY *list = gWinDriverObjects.Flink;
    while (list != &gWinDriverObjects)
    {
        PWIN_DRIVER_OBJECT pDrvObj = CONTAINING_RECORD(list, WIN_DRIVER_OBJECT, Link);

        list = list->Flink;

        RemoveEntryList(&pDrvObj->Link);

        status = IntWinDrvObjRemove(pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjRemoveDriverObject failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}
