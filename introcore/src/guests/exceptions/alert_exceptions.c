/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       alert_exceptions.c
/// @ingroup    group_exceptions
///

#include "alert_exceptions.h"
#include "crc32.h"
#include "guests.h"
#include "utils.h"


static DWORD
IntAlertGetHashForLinuxName(
    _In_ const WCHAR *Originator,
    _In_ const size_t MaxLength
    )
///
/// @brief Compute the crc32-hash for the provided string.
///
/// The crc32-hash is not computed in the following cases:
///     - if the provided string is the kernel name of the guest operation system the function returns kmExcNameKernel
///
/// @param[in] Originator   The string for witch the crc32-hash must be computed.
/// @param[in] MaxLength    The maximum length of the given buffer.
///
/// @retval     The value of the crc32-hash of the provided string.
///
{
    if (wstrnlen(Originator, MaxLength) == MaxLength)
    {
        return kmExcNameInvalid;
    }

    if (0 == wstrcasecmp(Originator, u"kernel"))
    {
        return kmExcNameKernel;
    }
    else
    {
        CHAR name[64];

        utf16toutf8(name, Originator, sizeof(name));

        return Crc32String(name, INITIAL_CRC_VALUE);
    }
}


static DWORD
IntAlertGetHashForWindowsName(
    _In_ const WCHAR *Originator,
    _In_ const size_t MaxLength
    )
///
/// @brief Compute the crc32-hash for the provided string.
///
/// The function parse the provided string (the string is a path) and extracts only the file name; the crc32-hash is
/// computed only for the extracted file name.
/// The crc32-hash is not computed in the following cases:
///     - if the provided string is the kernel name of the guest operation system the function returns kmExcNameKernel
///     - if the provided string is the hal name of the guest operation system the function returns kmExcNameHal
///
/// @param[in] Originator   The string for witch the crc32-hash must be computed.
/// @param[in] MaxLength    The maximum length of the buffer.
///
/// @retval     The value of the crc32-hash of the provided string.
///
{
    size_t i, len = wstrnlen(Originator, MaxLength);

    if (len == MaxLength)
    {
        return kmExcNameInvalid;
    }

    if (Originator[0] == u'\\' ||
        (((Originator[0] >= u'C' && Originator[0] <= u'Z') ||
          (Originator[0] >= u'c' && Originator[0] <= u'z')) &&
         Originator[1] == u':' &&
         Originator[2] == u'\\'))
    {
        for (i = len - 1; i > 0; i--)
        {
            if (Originator[i] == u'\\')
            {
                i++;
                break;
            }
        }
    }
    else
    {
        i = 0;
    }

    if (0 == wstrncasecmp_len(&Originator[i], u"ntkrnlmp.exe", len - i, CWSTRLEN(u"ntkrnlmp.exe")) ||
        0 == wstrncasecmp_len(&Originator[i], u"ntkrnlpa.exe", len - i, CWSTRLEN(u"ntkrnlpa.exe")) ||
        0 == wstrncasecmp_len(&Originator[i], u"ntkrpamp.exe", len - i, CWSTRLEN(u"ntkrpamp.exe")) ||
        0 == wstrncasecmp_len(&Originator[i], u"ntoskrnl.exe", len - i, CWSTRLEN(u"ntoskrnl.exe")))
    {
        return kmExcNameKernel;
    }
    else if (0 == wstrncasecmp_len(&Originator[i], u"hal.dll", len - i, CWSTRLEN(u"hal.dll")) ||
             0 == wstrncasecmp_len(&Originator[i], u"halmacpi.dll", len - i, CWSTRLEN(u"halmacpi.dll")) ||
             0 == wstrncasecmp_len(&Originator[i], u"halacpi.dll", len - i, CWSTRLEN(u"halacpi.dll")))
    {
        return kmExcNameHal;
    }
    else
    {
        return Crc32Wstring(&Originator[i], INITIAL_CRC_VALUE);
    }
}


static DWORD
IntAlertGetHashForName(
    _In_opt_ const WCHAR *Originator,
    _In_ BOOLEAN LinuxGuest,
    _In_ BOOLEAN KernelMode,
    _In_ size_t MaxLength
    )
///
/// @brief Compute the crc32-hash for the provided string.
///
/// If the provided string is missing the #kmExcNameNone/umExcNameNone is returned.
/// The function dispatch the crc32-hash compute to the appropriate function, depending on the operating system.
///
/// @param[in] Originator   The string for witch the crc32-hash must be computed.
/// @param[in] LinuxGuest   True if the provided string is used for a Linux guest, otherwise false.
/// @param[in] KernelMode   True if the provided string is used for kernel-mode, otherwise false.
/// @param[in] MaxLength    The maximum length of the given Originator buffer.
///
/// @retval     The value of the crc32-hash of the provided string.
///
{
    if (Originator == NULL)
    {
        if (KernelMode)
        {
            return kmExcNameNone;
        }
        else
        {
            return umExcNameNone;
        }
    }

    if (LinuxGuest)
    {
        return IntAlertGetHashForLinuxName(Originator, MaxLength);
    }
    else
    {
        return IntAlertGetHashForWindowsName(Originator, MaxLength);
    }
}


static DWORD
IntAlertGetEptExceptionFlags(
    _In_ const EVENT_EPT_VIOLATION *Event
    )
///
/// @brief Get the flags for an exception based on the information from the provided event.
///
/// This function always set the 32 and the 64 bits process/system flag; if the event was generated by a linux guest,
/// the exception flag for linux is set; the execute/read/write flags is set according to the event violation type.
///
/// @param[in] Event    The event structure provided by the integrator.
///
/// @retval The flags generated based on the information from the provided event.
///
{
    DWORD flags = EXCEPTION_FLG_32 | EXCEPTION_FLG_64;

    if (Event->Violation == IG_EPT_HOOK_EXECUTE)
    {
        flags |= EXCEPTION_FLG_EXECUTE;
    }
    else if (Event->Violation == IG_EPT_HOOK_READ)
    {
        flags |= EXCEPTION_FLG_READ;
    }
    else
    {
        flags |= EXCEPTION_FLG_WRITE;
    }

    if (Event->Header.Flags & ALERT_FLAG_LINUX)
    {
        flags |= EXCEPTION_FLG_LINUX;
    }

    return flags;
}


static void
IntAlertCreateCbSignature(
    _In_ const INTRO_CODEBLOCKS *CodeBlocks,
    _In_ BOOLEAN LinuxAlert,
    _In_ BOOLEAN ExecAlert,
    _Out_ ALERT_CB_SIGNATURE *Signature
    )
///
/// @brief Creates an alert-signature structure.
///
/// For each alert-structure is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility. If the alert was not generated from an execution violation the codeblocks in the
/// alert-signature are taken around the rip-index codeblock.
///
/// @param[in] CodeBlocks   Array of actual code block patterns.
/// @param[in] LinuxAlert   True if the signature is used for a Linux guest.
/// @param[in] ExecAlert    True if the alert was generated for an execution violation.
/// @param[out] Signature   The newly created alert signature structure.
///
{
    DWORD offset;

    if (!CodeBlocks->Valid)
    {
        Signature->Valid = FALSE;
        return;
    }

    offset = 0;

    Signature->Header.Version = ALERT_CB_SIGNATURE_VERSION;
    Signature->Flags = SIGNATURE_FLG_32 | SIGNATURE_FLG_64;

    if (LinuxAlert)
    {
        Signature->Flags |= SIGNATURE_FLG_LINUX;
    }

    if (CodeBlocks->RipCbIndex > ALERT_MAX_CODEBLOCKS)
    {
        ERROR("[ERROR] The index (%d) of the RIP's codeblock is grater than the ALERT_MAX_CODEBLOCKS (%d)\n",
              CodeBlocks->RipCbIndex, ALERT_MAX_CODEBLOCKS);

        Signature->Valid = FALSE;
        return;
    }

    if (CodeBlocks->Count > ALERT_MAX_CODEBLOCKS)
    {
        ERROR("[ERROR] The number of codeblocks (%d) is grater than the ALERT_MAX_CODEBLOCKS (%d)\n",
              CodeBlocks->RipCbIndex, ALERT_MAX_CODEBLOCKS);

        Signature->Valid = FALSE;
        return;
    }

    if (!ExecAlert)
    {
        if (CodeBlocks->RipCbIndex < (ALERT_HASH_COUNT / 2))
        {
            // [0; ALERT_HASH_COUNT]
            offset = 0;
        }
        else if (CodeBlocks->RipCbIndex + (ALERT_HASH_COUNT / 2) >= CodeBlocks->Count)
        {
            // [Count - ALERT_HASH_COUNT; Count]
            offset = CodeBlocks->Count >= ALERT_HASH_COUNT ? CodeBlocks->Count - ALERT_HASH_COUNT : 0;
        }
        else
        {
            // before & after rip
            offset = CodeBlocks->RipCbIndex - (ALERT_HASH_COUNT / 2);
        }
    }

    Signature->Count = (BYTE)MIN(CodeBlocks->Count, ALERT_HASH_COUNT);
    if (Signature->Count == 0)
    {
        WARNING("[WARNING] Codeblocks count is zero\n");
        Signature->Valid = FALSE;

        return;
    }

    Signature->Score = MAX(Signature->Count - 1, 1);

    for (int i = 0; i < Signature->Count; i++)
    {
        Signature->CodeBlocks[i] = CodeBlocks->CodeBlocks[i + offset].Value;
    }

    UtilQuickSort(Signature->CodeBlocks,
                  Signature->Count,
                  sizeof(Signature->CodeBlocks[0]));

    Signature->Valid = TRUE;
}


static void
IntAlertCreateProcessCreationSignature(
    _In_ DWORD PcType,
    _In_ BOOLEAN LinuxAlert,
    _Out_ ALERT_PROCESS_CREATION_SIGNATURE *Signature
    )
///
/// @brief Creates a process-creation alert-signature structure.
///
/// For each alert-structure is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
///
/// @param[in] PcType       The process creation violation type.
/// @param[in] LinuxAlert   True if the signature is used for a Linux guest.
/// @param[out] Signature   The newly created alert signature structure.
///
{
    Signature->Header.Version = ALERT_PROCESS_CREATION_SIGNATURE_VERSION;
    Signature->Flags = SIGNATURE_FLG_32 | SIGNATURE_FLG_64;

    if (LinuxAlert)
    {
        Signature->Flags |= SIGNATURE_FLG_LINUX;
    }

    Signature->CreateMask = PcType;

    Signature->Valid = TRUE;
}


static void
IntAlertCreateIdtSignature(
    _In_ const BYTE Entry,
    _In_ BOOLEAN LinuxAlert,
    _Out_ ALERT_IDT_SIGNATURE *Signature
    )
///
/// @brief Creates a IDT alert-signature structure.
///
/// For each alert-structure is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
///
/// @param[in] Entry        The entry number of the IDT entry.
/// @param[in] LinuxAlert   True if the signature is used for a Linux guest.
/// @param[out] Signature   The newly created alert signature structure.
///
{
    Signature->Header.Version = ALERT_IDT_SIGNATURE_VERSION;
    Signature->Flags = gGuest.Guest64 ? SIGNATURE_FLG_64 : SIGNATURE_FLG_32;

    if (LinuxAlert)
    {
        Signature->Flags |= SIGNATURE_FLG_LINUX;
    }

    Signature->Entry = Entry;

    Signature->Valid = TRUE;
}


static void
IntAlertCreateExportSignature(
    _In_ const INTRO_MODULE *Module,
    _In_ const char *FunctionName,
    _In_ DWORD FunctionNameHash,
    _In_ DWORD Delta,
    _In_ DWORD WriteSize,
    _In_ BOOLEAN LinuxEvent,
    _Out_ ALERT_EXPORT_SIGNATURE *Signature
    )
///
/// @brief Creates an export alert-signature structure.
///
/// For each alert-structure is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// If the function name is missing the kmExcNameAny is used as a function name.
///
/// @param[in] Module           A user-mode or kernel-mode module
/// @param[in] FunctionName     The function name from the provided module.
/// @param[in] FunctionNameHash The function name hash of the provided function.
/// @param[in] Delta            The number of bytes that are modified from the beginning of the write.
/// @param[in] WriteSize        The number of bytes that are modified.
/// @param[in] LinuxEvent       True if the signature is used for a Linux guest.
/// @param[out] Signature       The newly created alert signature structure.
///
{
    if (!Module->Valid || Module->Name[0] == 0)
    {
        Signature->Valid = FALSE;
        return;
    }

    Signature->Header.Version = ALERT_EXPORT_SIGNATURE_VERSION;
    Signature->Flags = SIGNATURE_FLG_32 | SIGNATURE_FLG_64;

    if (LinuxEvent)
    {
        Signature->Flags |= SIGNATURE_FLG_LINUX;
    }

    Signature->Library = IntAlertGetHashForName(Module->Name, LinuxEvent, FALSE, sizeof(Module->Name));
    if (Signature->Library == kmExcNameInvalid)
    {
        Signature->Valid = FALSE;
        return;
    }

    if (FunctionName[0])
    {
        Signature->Function = FunctionNameHash;
    }
    else
    {
        Signature->Function = umExcNameAny;
    }

    Signature->Delta = (BYTE)Delta;
    Signature->WriteSize = (BYTE)WriteSize;

    Signature->Valid = TRUE;
}


static INTSTATUS
IntAlertCreateEptException(
    _In_ const EVENT_EPT_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Inout_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an EPT violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function creates a user-mode or kernel-mode alert-exception based on the event flags; if the
/// #ALERT_FLAG_NOT_RING0 is set, an user-mode alert-exception the function creates an user-mode exception,
/// otherwise an kernel-mode alert-exception is created. The flags, originator, victim, type fields of the
/// alert-exception are extracted from the event. This function also creates code blocks and/or IDT signatures that is
/// assigned to the exception.
///
/// @param[in] Event        The event structure for EPT violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the information about the violation is invalid or incomplete.
///
{
    const WCHAR *originator = NULL;
    const WCHAR *victim = NULL;
    BOOLEAN linuxAlert;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    // Don't take into consideration the return driver, except when the original one it's missing. It's safer this way.
    // Anyway, we don't have a proper way on choosing between them...
    if (Event->Originator.Module.Valid)
    {
        originator = Event->Originator.Module.Name;
    }
    else if (Event->Originator.ReturnModule.Valid)
    {
        originator = Event->Originator.ReturnModule.Name;
    }

    linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;

    if (Event->Header.Flags & ALERT_FLAG_KM_UM)
    {
        ALERT_KUM_EXCEPTION *pException = Exception;
        BOOLEAN valid = FALSE;

        if (linuxAlert)
        {
            pException->Flags |= EXCEPTION_FLG_LINUX;
        }

        pException->Flags |= IntAlertGetEptExceptionFlags(Event);

        if (Event->Originator.Injection.User)
        {
            pException->Flags |= EXCEPTION_KUM_FLG_USER;
            pException->Originator = Crc32StringLen(Event->Originator.Process.ImageName,
                                                    INITIAL_CRC_VALUE,
                                                    sizeof(Event->Originator.Process.ImageName),
                                                    &valid);
            if (!valid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }

        }
        else if (Event->Originator.Injection.Kernel)
        {
            pException->Flags |= EXCEPTION_KUM_FLG_KERNEL;
            pException->Originator = IntAlertGetHashForName(Event->Originator.ReturnModule.Name,
                                                            linuxAlert,
                                                            TRUE,
                                                            sizeof(Event->Originator.ReturnModule.Name));
            if (pException->Originator == kmExcNameInvalid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }
        }
        else
        {
            pException->Originator = IntAlertGetHashForName(originator,
                                                            linuxAlert,
                                                            TRUE,
                                                            sizeof(Event->Originator.Module.Name));
            if (pException->Originator == kmExcNameInvalid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }
        }

        if (Event->Victim.Type == introObjectTypeUmModule)
        {
            if (Event->ZoneTypes & ZONE_LIB_IMPORTS)
            {
                pException->Type = kumObjModuleImports;
            }
            else if (Event->ZoneTypes & ZONE_LIB_EXPORTS)
            {
                pException->Type = kumObjModuleExports;
            }
            else
            {
                pException->Type = kumObjModule;
            }
        }
        else
        {
            ERROR("[ERROR] Invalid victim type (%d) for kernel-user exceptions!", Event->Victim.Type);
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (Event->Violation != IG_EPT_HOOK_EXECUTE)
        {
            pException->Victim = IntAlertGetHashForName(Event->Victim.Module.Name,
                                                        linuxAlert,
                                                        FALSE,
                                                        sizeof(Event->Victim.Module.Name));
            if (pException->Victim == umExcNameInvalid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }
        }
        else
        {
            pException->Victim = umExcNameAny;
            pException->Originator = umExcNameNone;
        }

        pException->Process = Crc32StringLen(Event->Header.CurrentProcess.ImageName,
                                             INITIAL_CRC_VALUE,
                                             sizeof(Event->Header.CurrentProcess.ImageName),
                                             &valid);
        if (!valid)
        {
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        IntAlertCreateCbSignature(&Event->CodeBlocks,
                                  linuxAlert,
                                  Event->Violation == IG_EPT_HOOK_EXECUTE,
                                  &pException->CodeBlocks);
    }
    else if (!(Event->Header.Flags & ALERT_FLAG_NOT_RING0))
    {
        ALERT_KM_EXCEPTION *pKmException = Exception;

        if ((Event->Victim.Type == introObjectTypeKmModule && !Event->Victim.Module.Valid) ||
                ((Event->Victim.Type == introObjectTypeDriverObject ||
                  Event->Victim.Type == introObjectTypeFastIoDispatch) &&
                 !Event->Victim.DriverObject.Valid))
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (linuxAlert)
        {
            pKmException->Flags |= SIGNATURE_FLG_LINUX;
        }

        pKmException->Flags |= IntAlertGetEptExceptionFlags(Event);

        pKmException->Originator = IntAlertGetHashForName(originator,
                                                          linuxAlert,
                                                          TRUE,
                                                          sizeof(Event->Originator.Module.Name));
        if (pKmException->Originator == kmExcNameInvalid)
        {
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        if (Event->Victim.Type == introObjectTypeKmModule ||
                Event->Victim.Type == introObjectTypeSsdt ||
                Event->Victim.Type == introObjectTypeTokenPrivs ||
                (linuxAlert && (Event->Victim.Type == introObjectTypeVdso ||
                                Event->Victim.Type == introObjectTypeVsyscall)))
        {
            victim = Event->Victim.Module.Name;

            if (Event->Victim.Type == introObjectTypeVsyscall)
            {
                pKmException->Victim = kmExcNameVsyscall;
            }
            else if (Event->Victim.Type == introObjectTypeVdso)
            {
                pKmException->Victim = kmExcNameVdso;
            }
            else if (Event->Victim.Type == introObjectTypeTokenPrivs)
            {
                pKmException->Victim = Crc32String(Event->Header.CurrentProcess.ImageName, INITIAL_CRC_VALUE);
            }
            else
            {
                pKmException->Victim = IntAlertGetHashForName(victim,
                                                              linuxAlert,
                                                              TRUE,
                                                              sizeof(Event->Victim.Module.Name));
                if (pKmException->Victim == kmExcNameInvalid)
                {
                    return INT_STATUS_INVALID_DATA_SIZE;
                }
            }

            if (Event->Victim.Type == introObjectTypeSsdt)
            {
                pKmException->Type = kmObjSsdt;
            }
            else if (Event->Victim.Type == introObjectTypeTokenPrivs)
            {
                pKmException->Type = kmObjTokenPrivs;
            }
            else if (Event->ZoneTypes & ZONE_LIB_IMPORTS)
            {
                pKmException->Type = kmObjDriverImports;
            }
            else if (Event->ZoneTypes & ZONE_LIB_EXPORTS)
            {
                pKmException->Type = kmObjDriverExports;
            }
            else if (Event->ZoneTypes & ZONE_LIB_CODE)
            {
                pKmException->Type = kmObjDriverCode;
            }
            else if (Event->ZoneTypes & ZONE_LIB_DATA)
            {
                pKmException->Type = kmObjDriverData;
            }
            else if (Event->ZoneTypes & ZONE_LIB_RESOURCES)
            {
                pKmException->Type = kmObjDriverResources;
            }
            else
            {
                return INT_STATUS_NOT_SUPPORTED;
            }
        }
        else if (Event->Victim.Type == introObjectTypeDriverObject ||
                 Event->Victim.Type == introObjectTypeFastIoDispatch)
        {
            BOOLEAN valid = FALSE;
            victim = Event->Victim.DriverObject.Name;

            pKmException->Victim = Crc32WstringLen(victim,
                                                   INITIAL_CRC_VALUE,
                                                   sizeof(Event->Victim.DriverObject.Name),
                                                   &valid);
            if (!valid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }

            if (Event->Victim.Type == introObjectTypeDriverObject)
            {
                pKmException->Type = kmObjDrvObj;
            }
            else if (Event->Victim.Type == introObjectTypeFastIoDispatch)
            {
                pKmException->Type = kmObjFastIo;
            }
        }
        else if (Event->Victim.Type == introObjectTypeIdt)
        {
            pKmException->Victim = kmExcNameAny;
            pKmException->Type = kmObjIdt;

            IntAlertCreateIdtSignature(Event->Victim.IdtEntry, linuxAlert, &pKmException->Idt);
        }
        else if (Event->Victim.Type == introObjectTypeKmLoggerContext)
        {
            pKmException->Victim = kmExcNameAny;
            pKmException->Type = kmObjLoggerCtx;
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        IntAlertCreateCbSignature(&Event->CodeBlocks,
                                  linuxAlert,
                                  Event->Violation == IG_EPT_HOOK_EXECUTE,
                                  &pKmException->CodeBlocks);
    }
    else
    {
        ALERT_UM_EXCEPTION *pUmException = Exception;
        BOOLEAN valid;

        if (linuxAlert)
        {
            pUmException->Flags |= SIGNATURE_FLG_LINUX;
        }

        if ((Event->Victim.Type != introObjectTypeUmModule &&
             Event->Victim.Type != introObjectTypeUmGenericNxZone &&
             Event->Victim.Type != introObjectTypeSudExec) ||
            (!Event->Header.CurrentProcess.Valid))
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        pUmException->Flags = IntAlertGetEptExceptionFlags(Event);

        if (Event->Victim.Type == introObjectTypeUmModule)
        {
            if (Event->ZoneTypes & ZONE_LIB_IMPORTS)
            {
                pUmException->Type = umObjModuleImports;
            }
            else if (Event->ZoneTypes & ZONE_LIB_EXPORTS)
            {
                pUmException->Type = umObjModuleExports;
            }
            else
            {
                pUmException->Type = umObjModule;
            }
        }
        else if (Event->Victim.Type == introObjectTypeUmGenericNxZone)
        {
            pUmException->Type = umObjNxZone;
        }
        else if (Event->Victim.Type == introObjectTypeSudExec)
        {
            pUmException->Type = umObjSharedUserData;
        }

        if (Event->Violation != IG_EPT_HOOK_EXECUTE)
        {
            pUmException->Originator = IntAlertGetHashForName(originator,
                                                              linuxAlert,
                                                              FALSE,
                                                              sizeof(Event->Originator.Module.Name));
            if (pUmException->Originator == umExcNameInvalid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }

            pUmException->Victim = IntAlertGetHashForName(Event->Victim.Module.Name,
                                                          linuxAlert,
                                                          FALSE,
                                                          sizeof(Event->Victim.Module.Name));
            if (pUmException->Victim == umExcNameInvalid)
            {
                return INT_STATUS_INVALID_DATA_SIZE;
            }
        }
        else
        {
            pUmException->Victim = umExcNameAny;
            pUmException->Originator = umExcNameNone;
        }

        pUmException->Process = Crc32StringLen(Event->Header.CurrentProcess.ImageName,
                                               INITIAL_CRC_VALUE,
                                               sizeof(Event->Header.CurrentProcess.ImageName),
                                               &valid);
        if (!valid)
        {
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        IntAlertCreateCbSignature(&Event->CodeBlocks,
                                  linuxAlert,
                                  Event->Violation == IG_EPT_HOOK_EXECUTE,
                                  &pUmException->CodeBlocks);
    }

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateMsrException(
    _In_ const EVENT_MSR_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Out_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an MSR violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function also creates codeblocks (if any) signatures that is assigned to the exception.
///
/// @param[in] Event        The event structure for MSR violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
///
{
    ALERT_KM_EXCEPTION *pKmException = Exception;
    const WCHAR *originator = NULL;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    if (Event->Originator.Module.Valid)
    {
        originator = Event->Originator.Module.Name;
    }

    pKmException->Flags = EXCEPTION_FLG_32 | EXCEPTION_FLG_64 | EXCEPTION_FLG_WRITE;

    if (linuxAlert)
    {
        pKmException->Flags |= EXCEPTION_FLG_LINUX;
    }

    pKmException->Victim = kmExcNameAny;
    pKmException->Type = kmObjMsr;
    pKmException->Originator = IntAlertGetHashForName(originator,
                                                      linuxAlert,
                                                      TRUE,
                                                      sizeof(Event->Originator.Module.Name));
    if (pKmException->Originator == kmExcNameInvalid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    IntAlertCreateCbSignature(&Event->CodeBlocks, linuxAlert, FALSE, &pKmException->CodeBlocks);

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateCrException(
    _In_ const EVENT_CR_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Out_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an CR violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function also creates codeblocks (if any) signatures that is assigned to the exception.
///
/// @param[in] Event        The event structure for CR violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
///
{
    ALERT_KM_EXCEPTION *pKmException = Exception;
    const WCHAR *originator = NULL;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    if (Event->Originator.Module.Valid)
    {
        originator = Event->Originator.Module.Name;
    }

    pKmException->Flags = EXCEPTION_FLG_32 |  EXCEPTION_FLG_64 |
                          EXCEPTION_KM_FLG_SMEP | EXCEPTION_KM_FLG_SMAP | EXCEPTION_FLG_WRITE;

    if (linuxAlert)
    {
        pKmException->Flags |= EXCEPTION_FLG_LINUX;
    }

    pKmException->Victim = kmExcNameAny;
    pKmException->Type = kmObjCr4;
    pKmException->Originator = IntAlertGetHashForName(originator,
                                                      linuxAlert,
                                                      TRUE,
                                                      sizeof(Event->Originator.Module.Name));
    if (pKmException->Originator == kmExcNameInvalid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    IntAlertCreateCbSignature(&Event->CodeBlocks, linuxAlert, FALSE, &pKmException->CodeBlocks);

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateInjectionException(
    _In_ const EVENT_MEMCOPY_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Out_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an Injection violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function also creates export (if any) signatures that is assigned to the exception.
///
/// @param[in] Event        The event structure for MSR violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the originator/victim is invalid.
///
{
    ALERT_UM_EXCEPTION *pException = Exception;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;
    BOOLEAN valid;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    if (Event->Originator.Process.ImageName[0] == 0 ||
        Event->Victim.Process.ImageName[0] == 0)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    pException->Flags = EXCEPTION_FLG_32 | EXCEPTION_FLG_64;

    if (linuxAlert)
    {
        pException->Flags |= EXCEPTION_FLG_LINUX;
    }

    switch (Event->ViolationType)
    {
    case memCopyViolationRead:
        pException->Flags |= EXCEPTION_FLG_READ;
        break;
    default:
        pException->Flags |= EXCEPTION_FLG_WRITE;
        break;
    }

    if (Event->ViolationType == memCopyViolationSetContextThread)
    {
        pException->Type = umObjProcessThreadContext;
    }
    else if (Event->ViolationType == memCopyViolationQueueApcThread)
    {
        pException->Type = umObjProcessApcThread;
    }
    else if (Event->ViolationType == memCopyViolationInstrument)
    {
        pException->Type = umObjProcessInstrumentation;
    }
    else
    {
        pException->Type = umObjProcess;
    }

    pException->Process = umExcNameAny;
    pException->Originator = Crc32StringLen(Event->Originator.Process.ImageName,
                                            INITIAL_CRC_VALUE,
                                            sizeof(Event->Originator.Process.ImageName),
                                            &valid);
    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    pException->Victim = Crc32StringLen(Event->Victim.Process.ImageName,
                                        INITIAL_CRC_VALUE,
                                        sizeof(Event->Victim.Process.ImageName),
                                        &valid);
    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    IntAlertCreateExportSignature(&Event->Victim.Module,
                                  Event->FunctionName,
                                  Event->FunctionNameHash,
                                  Event->Delta,
                                  Event->CopySize,
                                  linuxAlert,
                                  &pException->Export);

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateProcessCreationException(
    _In_ const EVENT_PROCESS_CREATION_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Inout_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an process-creation violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function also creates process-creation (if any) signatures that is assigned to the exception.
///
/// @param[in] Event        The event structure for process-creation violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the originator/victim is invalid.
///
{
    ALERT_UM_EXCEPTION *pException = Exception;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;
    BOOLEAN valid;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    if (Event->Originator.ImageName[0] == 0 ||
        Event->Victim.ImageName[0] == 0)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (linuxAlert)
    {
        pException->Flags |= EXCEPTION_FLG_LINUX;
    }

    pException->Flags |= EXCEPTION_FLG_32 | EXCEPTION_FLG_64 | EXCEPTION_FLG_EXECUTE;
    pException->Type = Event->PcType ? umObjProcessCreation : umObjProcessCreationDpi;
    pException->Originator = Crc32StringLen(Event->Originator.ImageName,
                                            INITIAL_CRC_VALUE,
                                            sizeof(Event->Originator.ImageName),
                                            &valid);
    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    pException->Victim = Crc32StringLen(Event->Victim.ImageName,
                                        INITIAL_CRC_VALUE,
                                        sizeof(Event->Victim.ImageName),
                                        &valid);
    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }
    pException->Process = umExcNameAny;

    if (Event->PcType != 0)
    {
        IntAlertCreateProcessCreationSignature(Event->PcType, linuxAlert, &pException->ProcessCreation);
    }

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateModuleLoadException(
    _In_ const EVENT_MODULE_LOAD_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Out_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an module-load violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
///
/// @param[in] Event        The event structure for module-load violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the originator/victim is invalid.
///
{
    ALERT_UM_EXCEPTION *pException = Exception;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;
    BOOLEAN valid;

    UNREFERENCED_PARAMETER(LogErrors);

    header->Valid = FALSE;

    if (Event->Originator.Module.Name[0] == 0 ||
        Event->Victim.ImageName[0] == 0)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    pException->Flags = EXCEPTION_FLG_32 | EXCEPTION_FLG_64;

    if (linuxAlert)
    {
        pException->Flags |= EXCEPTION_FLG_LINUX;
    }

    pException->Originator = IntAlertGetHashForName(Event->Originator.Module.Name,
                                                    linuxAlert,
                                                    FALSE,
                                                    sizeof(Event->Originator.Module.Name));
    if (pException->Originator == kmExcNameInvalid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    pException->Victim = Crc32StringLen(Event->Victim.ImageName,
                                        INITIAL_CRC_VALUE,
                                        sizeof(Event->Victim.ImageName),
                                        &valid);
    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    pException->Process = pException->Victim;
    pException->Flags |= EXCEPTION_FLG_WRITE;
    pException->Type = umObjModuleLoad;

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateIntegrityException(
    _In_ const EVENT_INTEGRITY_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _In_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an integrity violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
///
/// @param[in] Event        The event structure for integrity violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the current guest operating system is Linux.
///
{
    ALERT_KM_EXCEPTION *pKmException = Exception;
    const WCHAR *originator = NULL;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;
    BOOLEAN valid = TRUE;

    header->Valid = FALSE;

    if (gGuest.OSType == introGuestLinux)
    {
        if (LogErrors)
        {
            ERROR("[ERROR] Integrity exceptions are not supported on linux guests!\n");
        }

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Event->Victim.Type == introObjectTypeDriverObject)
    {
        pKmException->Type = kmObjDrvObj;
    }
    else if (Event->Victim.Type == introObjectTypeFastIoDispatch)
    {
        pKmException->Type = kmObjFastIo;
    }
    else if (Event->Victim.Type == introObjectTypeKmLoggerContext)
    {
        pKmException->Type = kmObjLoggerCtx;
    }
    else if (Event->Victim.Type == introObjectTypeIdt)
    {
        pKmException->Type = kmObjIdt;
    }
    else if (Event->Victim.Type == introObjectTypeTokenPrivs)
    {
        pKmException->Type = kmObjTokenPrivs;
    }
    else if (Event->Victim.Type == introObjectTypeSecDesc)
    {
        pKmException->Type = kmObjSecDesc;
    }
    else if (Event->Victim.Type == introObjectTypeAcl)
    {
        pKmException->Type = kmObjAcl;
    }
    else if (Event->Victim.Type == introObjectTypeHalPerfCounter)
    {
        pKmException->Type = kmObjHalPerfCnt;
    }
    else if (Event->Victim.Type == introObjectTypeSudIntegrity)
    {
        pKmException->Type = kmObjSudModification;
    }
    else if (Event->Victim.Type == introObjectTypeInterruptObject)
    {
        pKmException->Type = kmObjInterruptObject;
    }
    else
    {
        if (LogErrors)
        {
            ERROR("[ERROR] The given event is not supported: %d!\n", Event->Victim.Type);
        }

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Event->Originator.Module.Valid)
    {
        originator = Event->Originator.Module.Name;
    }

    pKmException->Flags = EXCEPTION_FLG_32 | EXCEPTION_FLG_64 | EXCEPTION_KM_FLG_INTEGRITY | EXCEPTION_FLG_WRITE;

    if (Event->Victim.Type == introObjectTypeTokenPrivs ||
        Event->Victim.Type == introObjectTypeSecDesc ||
        Event->Victim.Type == introObjectTypeAcl ||
        Event->Victim.Type == introObjectTypeSudIntegrity)
    {
        pKmException->Originator = kmExcNameNone;
    }
    else
    {
        pKmException->Originator = IntAlertGetHashForName(originator,
                                                          FALSE,
                                                          TRUE,
                                                          sizeof(Event->Originator.Module.Name));
        if (pKmException->Originator == kmExcNameInvalid)
        {
            return INT_STATUS_INVALID_DATA_SIZE;
        }
    }

    switch (Event->Victim.Type)
    {
        case introObjectTypeFastIoDispatch:
        case introObjectTypeDriverObject:
            if (!Event->Victim.DriverObject.Valid)
            {
                return INT_STATUS_NOT_SUPPORTED;
            }

            pKmException->Victim = Crc32WstringLen(Event->Victim.DriverObject.Name,
                                                   INITIAL_CRC_VALUE,
                                                   sizeof(Event->Victim.DriverObject.Name),
                                                   &valid);
            break;

        case introObjectTypeTokenPrivs:
        case introObjectTypeSecDesc:
        case introObjectTypeAcl:
            pKmException->Victim = Crc32StringLen(Event->Victim.Process.ImageName,
                                                  INITIAL_CRC_VALUE,
                                                  sizeof(Event->Victim.Process.ImageName),
                                                  &valid);
            break;

        case introObjectTypeSudIntegrity:
        {
            char buffer[sizeof(Event->Victim.Name) / 2];

            utf16toutf8(buffer, Event->Victim.Name, sizeof(buffer));

            pKmException->Victim = Crc32StringLen(buffer,
                                                  INITIAL_CRC_VALUE,
                                                  sizeof(buffer),
                                                  &valid);
            break;
        }

        default:
            pKmException->Victim = kmExcNameAny;
            break;
    }

    if (!valid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }


    if (Event->Victim.Type == introObjectTypeIdt ||
        Event->Victim.Type == introObjectTypeInterruptObject)
    {
        IntAlertCreateIdtSignature(Event->Victim.IdtEntry, FALSE, &pKmException->Idt);
    }

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntAlertCreateDtrException(
    _In_ const EVENT_DTR_VIOLATION *Event,
    _In_ BOOLEAN LogErrors,
    _Out_ void *Exception
    )
///
/// @brief Creates an alert-exception structure from an process-creation violation event.
///
/// For each alert-exception is assigned an internal version that is incremented for every change in the structure that
/// breaks the backwards-compatibility.
/// This function also creates code-blocks (if any) signatures that is assigned to the exception.
///
/// @param[in] Event        The event structure for process-creation violation.
/// @param[in] LogErrors    True if the function should log errors, otherwise false.
/// @param[out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the victim type is not kmObjIdtr or kmObjGdtr.
///
{
    ALERT_KM_EXCEPTION *pKmException = Exception;
    BOOLEAN linuxAlert = (Event->Header.Flags & ALERT_FLAG_LINUX) != 0;
    const WCHAR *originator = NULL;
    INTRO_ALERT_EXCEPTION_HEADER *header = Exception;

    header->Valid = FALSE;

    if (Event->Victim.Type == introObjectTypeIdtr)
    {
        pKmException->Type = kmObjIdtr;
    }
    else if (Event->Victim.Type == introObjectTypeGdtr)
    {
        pKmException->Type = kmObjGdtr;
    }
    else
    {
        if (LogErrors)
        {
            ERROR("[ERROR] The given event is not supported: %d!\n", Event->Victim.Type);
        }

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Event->Originator.Module.Valid)
    {
        originator = Event->Originator.Module.Name;
    }

    pKmException->Flags = (gGuest.Guest64 ? EXCEPTION_FLG_64 : EXCEPTION_FLG_32) | EXCEPTION_FLG_WRITE;

    if (linuxAlert)
    {
        pKmException->Flags |= EXCEPTION_FLG_LINUX;
    }

    pKmException->Victim = kmExcNameAny;
    pKmException->Originator = IntAlertGetHashForName(originator,
                                                      linuxAlert,
                                                      TRUE,
                                                      sizeof(Event->Originator.Module.Name));
    if (pKmException->Originator == kmExcNameInvalid)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    IntAlertCreateCbSignature(&Event->CodeBlocks, linuxAlert, FALSE, &pKmException->CodeBlocks);

    header->ViolationFlags = Event->Header.Flags;
    header->Valid = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntAlertCreateException(
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN LogErrors,
    _Inout_ void *Exception
    )
///
/// @brief          This function will dispatch the exception creation to the appropriate function,
///                 depending on the event type.
///
/// @param[in]      Event       The event structure for process-creation violation.
/// @param[in]      Type        The type of the event.
/// @param[in]      LogErrors   True if the function should log errors, otherwise False.
/// @param[in, out] Exception   A raw buffer to store the alert-exception.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the provided type is not supported.
///
{
    INTRO_ALERT_EXCEPTION_HEADER *pHeader = Exception;

    if (Type == introEventEptViolation)
    {
        if (!(((const EVENT_EPT_VIOLATION *)Event)->Header.Flags & ALERT_FLAG_KM_UM))
        {
            pHeader->Version = ALERT_KUM_EXCEPTION_VERSION;
        }
        else if (!(((const EVENT_EPT_VIOLATION *)Event)->Header.Flags & ALERT_FLAG_NOT_RING0))
        {
            pHeader->Version = ALERT_KM_EXCEPTION_VERSION;
        }
        else
        {
            pHeader->Version = ALERT_UM_EXCEPTION_VERSION;
        }
    }
    else if (introEventMsrViolation == Type ||
             introEventCrViolation == Type ||
             introEventDtrViolation == Type ||
             introEventIntegrityViolation == Type)
    {
        pHeader->Version = ALERT_KM_EXCEPTION_VERSION;
    }
    else if (introEventInjectionViolation == Type ||
             introEventProcessCreationViolation == Type ||
             introEventModuleLoadViolation == Type)
    {
        pHeader->Version = ALERT_UM_EXCEPTION_VERSION;
    }

    switch (Type)
    {
    case introEventEptViolation:
        return IntAlertCreateEptException(Event, LogErrors, Exception);

    case introEventMsrViolation:
        return IntAlertCreateMsrException(Event, LogErrors, Exception);

    case introEventCrViolation:
        return IntAlertCreateCrException(Event, LogErrors, Exception);

    case introEventInjectionViolation:
        return IntAlertCreateInjectionException(Event, LogErrors, Exception);

    case introEventIntegrityViolation:
        return IntAlertCreateIntegrityException(Event, LogErrors, Exception);

    case introEventDtrViolation:
        return IntAlertCreateDtrException(Event, LogErrors, Exception);

    case introEventProcessCreationViolation:
        return IntAlertCreateProcessCreationException(Event, LogErrors, Exception);

    case introEventModuleLoadViolation:
        return IntAlertCreateModuleLoadException(Event, LogErrors, Exception);

    default:
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntAlertCreateExceptionInEvent(
    _Inout_ void *Event,
    _In_ INTRO_EVENT_TYPE Type
    )
///
/// @brief This function creates an alert-exception for each alert sent to the integrator.
///
/// @param[in] Event        The event structure for process-creation violation.
/// @param[in] Type         The type of the event.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If the provided type is not supported.
///
{
    if (!IntAlertIsEventTypeViolation(Type))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return IntAlertCreateException(Event, Type, FALSE, &((INTRO_VIOLATION_HEADER *)Event)->Exception);
}
