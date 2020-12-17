/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       exceptions_kern.c
/// @ingroup    group_exceptions
/// @brief      Kernel mode exceptions
///

#include "exceptions.h"
#include "guests.h"
#include "lixstack.h"
#include "winpe.h"
#include "winstack.h"
#include "lixksym.h"
#include "crc32.h"


extern char gExcLogLine[2 * ONE_KILOBYTE];


static int
IntExceptPrintLixKmDrvInfo(
    _In_ KERNEL_DRIVER *Driver,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    )
///
/// @brief Print the information about the provided #KERNEL_DRIVER (Linux guest).
///
/// @param[in]  Driver          The driver object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
/// @param[in]  NameAlignment   The alignment of the chars in the buffer.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;

    if (NULL == Driver)
    {
        return snprintf(Line, MaxLength, "%s(%s)", Header, EXCEPTION_NO_NAME);
    }

    if (*(char *)Driver->Name)
    {
        ret = snprintf(Line, MaxLength, "%s(%-*s", Header, NameAlignment, (char *)Driver->Name);
    }
    else
    {
        ret = snprintf(Line, MaxLength, "%s(%s", Header, EXCEPTION_NO_NAME);
    }

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " [0x%08x], %016llx", Driver->NameHash, Driver->BaseVa);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    return total;
}


int
IntExceptPrintWinKmModInfo(
    _In_ KERNEL_DRIVER *Module,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    )
///
/// @brief Print the information about the provided #KERNEL_DRIVER (windows guest).
///
/// @param[in]  Module          The driver object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
/// @param[in]  NameAlignment   The alignment of the chars in the buffer.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;
    WCHAR *wName;
    char name[MAX_PATH];

    if (NULL == Module)
    {
        return snprintf(Line, MaxLength, "%s(%s)", Header, EXCEPTION_NO_NAME);
    }

    wName = Module->Win.Path ? Module->Win.Path : Module->Name ? Module->Name : NULL;

    if (wName)
    {
        utf16toutf8(name, wName, sizeof(name));
    }
    else
    {
        memcpy(name, EXCEPTION_NO_NAME, sizeof(EXCEPTION_NO_NAME));
    }

    if (NameAlignment)
    {
        ret = snprintf(Line, MaxLength, "%s(%-*s", Header, NameAlignment, name);
    }
    else
    {
        ret = snprintf(Line, MaxLength, "%s(%s", Header, name);
    }

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " [0x%08x], %0*llx", Module->NameHash, gGuest.WordSize * 2, Module->BaseVa);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    if (Module->Win.TimeDateStamp)
    {
        ret = snprintf(Line, MaxLength, ", VerInfo: %x:%llx", Module->Win.TimeDateStamp, Module->Size);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    return total;
}


static int
IntExceptPrintMsrInfo(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength
    )
///
/// @brief Print the information about the modified MSR.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
///
/// @retval     The number of written chars.
///
{
    const char *msrName = NULL;
    int ret = 0, total = 0;

    ret = snprintf(Line, MaxLength, "%s: (%08x", Header, Victim->Msr.Msr);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    if (Victim->Msr.Msr == IG_IA32_SYSENTER_CS)
    {
        msrName = "SYSENTER_CS";
    }
    else if (Victim->Msr.Msr == IG_IA32_SYSENTER_ESP)
    {
        msrName = "SYSENTER_ESP";
    }
    else if (Victim->Msr.Msr == IG_IA32_SYSENTER_EIP)
    {
        msrName = "SYSENTER_EIP";
    }
    else if (Victim->Msr.Msr == IG_IA32_STAR)
    {
        msrName = "STAR";
    }
    else if (Victim->Msr.Msr == IG_IA32_LSTAR)
    {
        msrName = "LSTAR";
    }

    if (msrName)
    {
        ret = snprintf(Line, MaxLength, ", %s", msrName);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            MaxLength -= ret;
            Line += ret;
            total += ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    ret = snprintf(Line, MaxLength, ", WriteInfo: (%016llx -> %016llx)",
                   Victim->WriteInfo.OldValue[0],
                   Victim->WriteInfo.NewValue[0]);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    if (Victim->Msr.NewDriverBase)
    {
        KERNEL_DRIVER *pMsrDrv = IntDriverFindByAddress(Victim->Msr.NewDriverBase);

        if (gGuest.OSType == introGuestWindows)
        {
            ret = IntExceptPrintWinKmModInfo(pMsrDrv, ", Module: ", Line, MaxLength, 0);

            if (ret < 0 || ret >= MaxLength)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
            }
            else
            {
                MaxLength -= ret;
                Line += ret;
                total += ret;
            }
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            ret = IntExceptPrintLixKmDrvInfo(pMsrDrv, ", Module: ", Line, MaxLength, 0);

            if (ret < 0 || ret >= MaxLength)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
            }
            else
            {
                MaxLength -= ret;
                Line += ret;
                total += ret;
            }

            if (pMsrDrv == gGuest.KernelDriver)
            {
                char symbol[LIX_SYMBOL_NAME_LEN];

                INTSTATUS status = IntKsymFindByAddress(Victim->WriteInfo.NewValue[0],
                                                        sizeof(symbol),
                                                        symbol,
                                                        NULL,
                                                        NULL);
                if (!INT_SUCCESS(status))
                {
                    memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
                }

                ret = snprintf(Line, MaxLength, ", %s", symbol);

                if (ret < 0 || ret >= MaxLength)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
                }
                else
                {
                    MaxLength -= ret;
                    Line += ret;
                    total += ret;
                }
            }
        }
    }

    return total;
}


static int
IntExceptPrintCrInfo(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength
    )
///
/// @brief Print the information about the modified CR.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
///
/// @retval     The number of written chars.
///
{
    int ret = 0, total = 0;

    ret = snprintf(Line, MaxLength, "%s%u", Header, Victim->Cr.Cr);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    if (Victim->Cr.Smep && Victim->Cr.Smap)
    {
        ret = snprintf(Line, MaxLength, ", (SMAP, SMEP)");

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            MaxLength -= ret;
            Line += ret;
            total += ret;
        }
    }
    else if (Victim->Cr.Smap)
    {
        ret = snprintf(Line, MaxLength, ", (SMEP)");

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            MaxLength -= ret;
            Line += ret;
            total += ret;
        }
    }
    else if (Victim->Cr.Smep)
    {
        ret = snprintf(Line, MaxLength, ", (SMAP)");

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            MaxLength -= ret;
            Line += ret;
            total += ret;
        }
    }

    ret = snprintf(Line, MaxLength, ", WriteInfo: (%u, %016llx -> %016llx)",
                   Victim->WriteInfo.AccessSize,
                   Victim->WriteInfo.OldValue[0],
                   Victim->WriteInfo.NewValue[0]);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    return total;
}


static int
IntExceptPrintIdtInfo(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength
    )
///
/// @brief Print the information about the modified IDT entry.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
///
/// @retval     The number of written chars.
///
{
    int ret = 0, total = 0;
    QWORD entry, entryNo;
    char *prot;

    if (Victim->ZoneType == exceptionZoneIntegrity)
    {
        entry = Victim->Object.BaseAddress + Victim->Integrity.Offset;
        entryNo = Victim->Integrity.Offset / (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32);
        prot = "INTEGRITY";
    }
    else
    {
        entry = Victim->Ept.Gva;
        entryNo = (Victim->Ept.Gva - Victim->Object.BaseAddress) /
            (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32);
        prot = "EPT";
    }

    ret = snprintf(Line, MaxLength, "%s (IDT Base Address: %llx, IDT Entry modified: %llu (0x%016llx) (%s)",
                   Header, Victim->Object.BaseAddress, entryNo, entry, prot);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    ret = snprintf(Line, MaxLength, ", WriteInfo: (%u", Victim->WriteInfo.AccessSize);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    for (DWORD i = 0; i * sizeof(Victim->WriteInfo.NewValue[0]) < Victim->WriteInfo.AccessSize; i++)
    {
        ret = snprintf(Line, MaxLength, ", %016llx -> 0x%016llx",
                Victim->WriteInfo.OldValue[i],
                Victim->WriteInfo.NewValue[i]);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            MaxLength -= ret;
            Line += ret;
            total += ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    return total;
}


static int
IntExceptPrintDtrInfo(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength
    )
///
/// @brief Print the information about the modified IDTR/GDTR.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
///
/// @retval     The number of written chars.
///
{
    const char *dtrName = NULL;
    int ret = 0, total = 0;

    ret = snprintf(Line, MaxLength, "%s(", Header);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    if (Victim->Dtr.Type == introObjectTypeIdtr)
    {
        dtrName = "IDTR";
    }
    else if (Victim->Dtr.Type == introObjectTypeGdtr)
    {
        dtrName = "GDTR";
    }
    else
    {
        dtrName = "Unknown";
    }

    ret = snprintf(Line, MaxLength, "%s", dtrName);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    ret = snprintf(Line, MaxLength, ", WriteInfo: (%016llx -> %016llx)",
                   Victim->WriteInfo.OldValue[0],
                   Victim->WriteInfo.NewValue[0]);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    ret = snprintf(Line, MaxLength, ", DtrLimit: (%04llx -> %04llx)",
                   Victim->WriteInfo.OldValue[1],
                   Victim->WriteInfo.NewValue[1]);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        MaxLength -= ret;
        Line += ret;
        total += ret;
    }

    return total;
}


static void
IntExceptKernelLogLinuxInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a kernel-mode violation (Linux guest).
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    KERNEL_DRIVER *pDriver, *pRetDriver;
    char symbol[LIX_SYMBOL_NAME_LEN];
    DWORD modNameAlignment;
    INTSTATUS status;
    char *l;
    int ret, rem;

    pDriver = Originator->Original.Driver;
    pRetDriver = Originator->Return.Driver;

    modNameAlignment = 0;
    if (Victim->Object.Type == introObjectTypeKmModule)
    {
        KERNEL_DRIVER *pModDriver = Victim->Object.Module.Module;

        if (pModDriver && pDriver && pRetDriver)
        {
            modNameAlignment = (DWORD)MIN(MAX_PATH, MAX(pModDriver->NameLength, pDriver->NameLength));
        }

        if (pModDriver && pRetDriver)
        {
            if (modNameAlignment > 0)
            {
                modNameAlignment = (DWORD)MIN(MAX_PATH, MAX(pRetDriver->NameLength, modNameAlignment));
            }
            else
            {
                modNameAlignment = (DWORD)MIN(MAX_PATH, MAX(pModDriver->NameLength, pRetDriver->NameLength));
            }
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if (Victim->ZoneType == exceptionZoneIntegrity)
    {
        // No point in logging anything else, since the RIP is unknown
        ret = IntExceptPrintLixKmDrvInfo(pDriver, "Originator-> Module: ", l, rem, modNameAlignment);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else
    {
        char instr[ND_MIN_BUF_SIZE];
        LIX_TASK_OBJECT *pTask;

        if (Originator->Instruction)
        {
            NDSTATUS s = NdToText(Originator->Instruction, Originator->Original.Rip, sizeof(instr), instr);
            if (!ND_SUCCESS(s))
            {
                memcpy(instr, EXPORT_NAME_UNKNOWN, sizeof(EXPORT_NAME_UNKNOWN));
            }
        }
        else
        {
            memcpy(instr, EXCEPTION_NO_INSTRUCTION, sizeof(EXCEPTION_NO_INSTRUCTION));
        }

        if (pDriver == gGuest.KernelDriver)
        {
            status = IntKsymFindByAddress(Originator->Original.Rip, sizeof(symbol), symbol, NULL, NULL);
            if (!INT_SUCCESS(status))
            {
                memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
            }
        }
        else
        {
            symbol[0] = 0;
        }

        ret = IntExceptPrintLixKmDrvInfo(pDriver, "Originator-> Module: ", l, rem, modNameAlignment);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, ", RIP %016llx", Originator->Original.Rip);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Originator->Original.Section[0] != 0)
        {
            ret = snprintf(l, rem, " (%s)", Originator->Original.Section);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        if (symbol[0] != 0)
        {
            ret = snprintf(l, rem, " (%s)", symbol);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        if (instr[0] != 0)
        {
            ret = snprintf(l, rem, ", Instr: %s", instr);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        pTask = IntLixTaskGetCurrent(IG_CURRENT_VCPU);
        if (NULL != pTask)
        {
            LIX_TASK_OBJECT *pParent = IntLixTaskFindByGva(pTask->Parent);

            ret  = IntExceptPrintLixTaskInfo(pTask, ", Process: ", l, rem, 0);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            ret = IntExceptPrintLixTaskInfo(pParent, ", Parent: ", l, rem, 0);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);

        // Log the return driver too, if we have one and the rip is different
        if (pRetDriver && Originator->Original.Rip != Originator->Return.Rip)
        {
            l = gExcLogLine;
            rem = sizeof(gExcLogLine);

            if (pRetDriver == gGuest.KernelDriver)
            {
                status = IntKsymFindByAddress(Originator->Return.Rip, sizeof(symbol), symbol, NULL, NULL);
                if (!INT_SUCCESS(status))
                {
                    memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
                }
            }
            else
            {
                symbol[0] = 0;
            }

            ret = IntExceptPrintLixKmDrvInfo(pRetDriver, "Return    -> Module: ", l, rem, modNameAlignment);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            ret = snprintf(l, rem, ", RIP %016llx", Originator->Return.Rip);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            if (Originator->Return.Section[0] != 0)
            {
                ret = snprintf(l, rem, "(%s)", Originator->Return.Section);

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }
            }

            if (symbol[0] != 0)
            {
                ret = snprintf(l, rem, " (%s)", symbol);

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }
            }

            LOG("%s\n", gExcLogLine);
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if (Victim->ZoneType == exceptionZoneMsr)
    {
        IntExceptPrintMsrInfo(Victim, "Victim    -> Msr: ", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if ((Victim->Object.Type == introObjectTypeKmModule) ||
             (Victim->Object.Type == introObjectTypeVdso) ||
             (Victim->Object.Type == introObjectTypeVsyscall))
    {
        pDriver = Victim->Object.Module.Module;

        if (pDriver)
        {
            ret = IntExceptPrintLixKmDrvInfo(pDriver, "Victim    -> Module: ", l, rem, modNameAlignment);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }
        else if (Victim->Object.Type == introObjectTypeVdso)
        {
            ret = snprintf(l, rem, "Victim    -> Module: %*s", modNameAlignment, "[vdso]");

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }
        else if (Victim->Object.Type == introObjectTypeVsyscall)
        {
            ret = snprintf(l, rem, "Victim    -> Module: %*s", modNameAlignment, "[vsyscall]");

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        ret = snprintf(l, rem, ", Address: (%0llx, %0llx)",
                       Victim->Ept.Gva, Victim->Ept.Gpa);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (pDriver == gGuest.KernelDriver)
        {
            status = IntKsymFindByAddress(Victim->Ept.Gva, sizeof(symbol), symbol, NULL, NULL);
            if (!INT_SUCCESS(status))
            {
                memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
            }

            ret = snprintf(l, rem, ", %s", symbol);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        ret = 0;
        if (Victim->ZoneFlags & ZONE_WRITE)
        {
            ret = snprintf(l, rem, ", WriteInfo: (%u, %016llx -> %016llx)", Victim->WriteInfo.AccessSize,
                           Victim->WriteInfo.OldValue[0], Victim->WriteInfo.NewValue[0]);
        }
        else if (Victim->ZoneFlags & ZONE_READ)
        {
            ret = snprintf(l, rem, ", ReadInfo: (%u, %016llx)", Victim->ReadInfo.AccessSize, Victim->ReadInfo.Value[0]);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Victim->ZoneFlags)
        {
            ret = snprintf(l, rem, ", Flags:%s%s%s%s%s (0x%llx)",
                           (Victim->ZoneFlags & ZONE_LIB_IMPORTS) ? " IMPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_EXPORTS) ? " EXPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_CODE) ? " CODE" : "",
                           (Victim->ZoneFlags & ZONE_LIB_DATA) ? " DATA" : "",
                           (Victim->ZoneFlags & ZONE_LIB_RESOURCES) ? " RSRC" : "",
                           (unsigned long long)Victim->ZoneFlags);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->ZoneType == exceptionZoneCr)
    {
        ret = IntExceptPrintCrInfo(Victim, "Victim    -> Cr", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeIdt)
    {
        ret = IntExceptPrintIdtInfo(Victim, "Victim    -> Idt: ", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }

    if (Action == introGuestNotAllowed)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = snprintf(l, rem, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%sROOTKIT (kernel-mode) ",
                       gGuest.KernelBetaDetections ? " (B) " : " ");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        switch (Reason)
        {
        case introReasonSignatureNotMatched:
            ret = snprintf(l, rem, "(no sig)");
            break;
        case introReasonNoException:
            ret = snprintf(l, rem, "(no exc)");
            break;
        case introReasonExtraChecksFailed:
            ret = snprintf(l, rem, "(extra)");
            break;
        case introReasonInternalError:
            ret = snprintf(l, rem, "(error)");
            break;
        case introReasonValueNotMatched:
            ret = snprintf(l, rem, "(value)");
            break;
        case introReasonExportNotMatched:
            ret = snprintf(l, rem, "(export)");
            break;
        case introReasonValueCodeNotMatched:
            ret = snprintf(l, rem, "(value code)");
            break;
        case introReasonIdtNotMatched:
            ret = snprintf(l, rem, "(idt)");
            break;
        case introReasonVersionOsNotMatched:
            ret = snprintf(l, rem, "(version os)");
            break;
        case introReasonVersionIntroNotMatched:
            ret = snprintf(l, rem, "(version intro)");
            break;
        case introReasonProcessCreationNotMatched:
            ret = snprintf(l, rem, "(process creation)");
            break;
        case introReasonUnknown:
            ret = snprintf(l, rem, "(unknown)");
            break;
        default:
            ret = snprintf(l, rem, "(%d)", Reason);
            break;
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        snprintf(l, rem, " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n\n", gExcLogLine);
    }

    for (DWORD t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
    {
        if (NULL != Originator->StackTrace.Traces[t].ReturnModule)
        {

            if (Originator->StackTrace.Traces[t].ReturnModule == gGuest.KernelDriver)
            {
                status = IntKsymFindByAddress(Originator->StackTrace.Traces[t].CurrentRip,
                                              sizeof(symbol),
                                              symbol,
                                              NULL,
                                              NULL);
                if (!INT_SUCCESS(status))
                {
                    memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
                }
            }
            else
            {
                memcpy(symbol, EXCEPTION_NO_SYMBOL, sizeof(EXCEPTION_NO_SYMBOL));
            }

            LOG("[STACK TRACE] [at %llx] returning to [%s at %llx] %s",
                Originator->StackTrace.Traces[t].CurrentRip,
                (char *)((KERNEL_DRIVER *)Originator->StackTrace.Traces[t].ReturnModule)->Name,
                Originator->StackTrace.Traces[t].ReturnAddress, symbol);
        }
        else
        {
            LOG("[STACK TRACE] [at %llx]", Originator->StackTrace.Traces[t].CurrentRip);
        }
    }

}


static int
IntExceptPrintDrvObjInfo(
    _In_ WIN_DRIVER_OBJECT *DrvObj,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength
    )
///
/// @brief Print the information about the #WIN_DRIVER_OBJECT.
///
/// @param[in]  DrvObj          The #WIN_DRIVER_OBJECT object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;
    char name[MAX_PATH];

    if (NULL == DrvObj)
    {
        return snprintf(Line, MaxLength, "%s(%s)", Header, EXCEPTION_NO_NAME);
    }

    utf16toutf8(name, DrvObj->Name, sizeof(name));

    ret = snprintf(Line, MaxLength, "%s(%s", Header, name);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " [0x%08x], %0*llx, %0llx",
                   DrvObj->NameHash, gGuest.WordSize * 2, DrvObj->DriverObjectGva, DrvObj->DriverObjectGpa);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    if (DrvObj->FastIOTableAddress)
    {
        ret = snprintf(Line, MaxLength, ", %0*llx", gGuest.WordSize * 2, DrvObj->FastIOTableAddress);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    return total;
}


static void
IntExceptKernelLogWindowsInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a kernel-mode violation (windows guest).
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    KERNEL_DRIVER *pDriver, *pRetDriver;
    DWORD modNameAlignment;
    char *l;
    int ret, rem;

    pDriver = Originator->Original.Driver;
    pRetDriver = Originator->Return.Driver;

    modNameAlignment = 0;
    if (Victim->Object.Type == introObjectTypeKmModule || Victim->Object.Type == introObjectTypeVeAgent)
    {
        KERNEL_DRIVER *pModDriver = Victim->Object.Module.Module;

        if (pModDriver && pDriver)
        {
            modNameAlignment = MIN(MAX_PATH, MAX(pModDriver->Win.PathLength, pDriver->Win.PathLength));
        }

        if (pModDriver && pRetDriver)
        {
            if (modNameAlignment > 0)
            {
                modNameAlignment = MIN(MAX_PATH, MAX(pRetDriver->Win.PathLength, modNameAlignment));
            }
            else
            {
                modNameAlignment = MIN(MAX_PATH, MAX(pModDriver->Win.PathLength, pRetDriver->Win.PathLength));
            }
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if (Victim->ZoneType == exceptionZoneIntegrity)
    {
        // For token privileges, security descriptor integrity detection and SharedUsedData integrity detection,
        // originator will always be invalid, there is no reason to just log a "Originator no name" line.
        if (Victim->Object.Type != introObjectTypeTokenPrivs &&
            Victim->Object.Type != introObjectTypeSecDesc &&
            Victim->Object.Type != introObjectTypeAcl &&
            Victim->Object.Type != introObjectTypeSudIntegrity)
        {
            // No point in logging anything else, since the RIP is unknown
            ret = IntExceptPrintWinKmModInfo(pDriver, "Originator-> Module: ", l, rem, 0);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            LOG("%s\n", gExcLogLine);
        }
    }
    else
    {
        char instr[ND_MIN_BUF_SIZE];

        if (Originator->Instruction)
        {
            NDSTATUS ndstatus = NdToText(Originator->Instruction, Originator->Original.Rip, sizeof(instr), instr);
            if (!ND_SUCCESS(ndstatus))
            {
                memcpy(instr, EXPORT_NAME_UNKNOWN, sizeof(EXPORT_NAME_UNKNOWN));
            }
        }
        else
        {
            memcpy(instr, EXCEPTION_NO_INSTRUCTION, sizeof(EXCEPTION_NO_INSTRUCTION));
        }

        ret = IntExceptPrintWinKmModInfo(pDriver, "Originator-> Module: ", l, rem, modNameAlignment);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Original.Rip);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Originator->Original.Section[0] != 0)
        {
            ret = snprintf(l, rem, " (%s)", Originator->Original.Section);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        if (instr[0] != 0)
        {
            ret = snprintf(l, rem, ", Instr: %s", instr);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);

        if (Originator->Return.Driver && Originator->Original.Rip != Originator->Return.Rip)
        {
            l = gExcLogLine;
            rem = sizeof(gExcLogLine);

            ret = IntExceptPrintWinKmModInfo(pRetDriver, "Return    -> Module: ", l, rem, modNameAlignment);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Return.Rip);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            if (Originator->Return.Section[0] != 0)
            {
                ret = snprintf(l, rem, "(%s)", Originator->Return.Section);

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }
            }

            LOG("%s\n", gExcLogLine);
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if (Victim->ZoneType == exceptionZoneMsr)
    {
        ret = IntExceptPrintMsrInfo(Victim, "Victim    -> Msr: ", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeKmModule ||
             Victim->Object.Type == introObjectTypeSsdt ||
             Victim->Object.Type == introObjectTypeVeAgent)
    {
        pDriver = Victim->Object.Module.Module;

        ret = IntExceptPrintWinKmModInfo(pDriver, "Victim    -> Module: ", l, rem, modNameAlignment);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, ", Address: (%0*llx, %0*llx)",
                       gGuest.WordSize * 2, Victim->Ept.Gva,
                       gGuest.WordSize * 2, Victim->Ept.Gpa);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Victim->ZoneFlags & ZONE_WRITE)
        {
            ret = snprintf(l, rem, ", WriteInfo: (%u, %016llx -> %016llx)", Victim->WriteInfo.AccessSize,
                           Victim->WriteInfo.OldValue[0], Victim->WriteInfo.NewValue[0]);
        }
        else if (Victim->ZoneFlags & ZONE_READ)
        {
            ret = snprintf(l, rem, ", ReadInfo: (%u, %016llx)", Victim->ReadInfo.AccessSize, Victim->ReadInfo.Value[0]);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Victim->ZoneFlags)
        {
            ret = snprintf(l, rem, ", Flags:%s%s%s%s%s (0x%llx)",
                           (Victim->ZoneFlags & ZONE_LIB_IMPORTS) ? " IMPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_EXPORTS) ? " EXPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_CODE) ? " CODE" : "",
                           (Victim->ZoneFlags & ZONE_LIB_DATA) ? " DATA" : "",
                           (Victim->ZoneFlags & ZONE_LIB_RESOURCES) ? " RSRC" : "",
                           (unsigned long long)Victim->ZoneFlags);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);
    }
    else if ((Victim->Object.Type == introObjectTypeDriverObject) ||
             (Victim->Object.Type == introObjectTypeFastIoDispatch))
    {
        BOOLEAN fastIo = (Victim->Object.Type == introObjectTypeFastIoDispatch);

        if (fastIo)
        {
            ret = IntExceptPrintDrvObjInfo(Victim->Object.DriverObject, "Victim    -> FastIo: ", l, rem);
        }
        else
        {
            ret = IntExceptPrintDrvObjInfo(Victim->Object.DriverObject, "Victim    -> DrvObj: ", l, rem);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        pDriver = IntDriverFindByBase(Victim->Object.DriverObject->Owner);
        if (pDriver)
        {
            ret = IntExceptPrintWinKmModInfo(pDriver, ", Owner: ", l, rem, 0);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        ret = snprintf(l, rem, ", WriteInfo: (%u, %016llx -> %016llx)",
                       Victim->WriteInfo.AccessSize,
                       Victim->WriteInfo.OldValue[0],
                       Victim->WriteInfo.NewValue[0]);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Victim->ZoneType == exceptionZoneIntegrity)
        {
            ret = snprintf(l, rem, ", INTEGRITY");

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->ZoneType == exceptionZoneCr)
    {
        ret = IntExceptPrintCrInfo(Victim, "Victim    -> Cr", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeHalIntController)
    {
        LOG("Victim    -> Hal interrupt controller: (%0*llx, %0*llx), WriteInfo: (%d, %016llx -> %016llx)\n",
            gGuest.WordSize * 2, Victim->Ept.Gva, gGuest.WordSize * 2, Victim->Ept.Gpa,
            Victim->WriteInfo.AccessSize,
            Victim->WriteInfo.OldValue[0], Victim->WriteInfo.NewValue[0]);
    }
    else if (Victim->Object.Type == introObjectTypeHalHeap)
    {
        LOG("Victim    -> Hal heap execute: (%0*llx, %0*llx)\n",
            gGuest.WordSize * 2, Victim->Ept.Gva, gGuest.WordSize * 2, Victim->Ept.Gpa);
    }
    else if (Victim->Object.Type == introObjectTypeSudExec)
    {
        LOG("Victim    -> SharedUserData execute: (%0*llx, %0*llx)\n",
            gGuest.WordSize * 2, Victim->Ept.Gva, gGuest.WordSize * 2, Victim->Ept.Gpa);
    }
    else if (Victim->Object.Type == introObjectTypeIdt)
    {
        ret = IntExceptPrintIdtInfo(Victim, "Victim    -> Idt: ", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeSelfMapEntry)
    {
        LOG("Victim    -> Self map entry: %s [0x%08x] (%016llx, %016llx), "
            "WriteInfo: (%d, %016llx -> %016llx), Index: %08x\n",
            Victim->Object.Name, Victim->Object.NameHash,
            Victim->Ept.Gva, Victim->Ept.Gpa,
            Victim->WriteInfo.AccessSize,
            Victim->WriteInfo.OldValue[0],
            Victim->WriteInfo.NewValue[0],
            gGuest.Mm.SelfMapIndex);
    }
    else if (Victim->Object.Type == introObjectTypeKmLoggerContext)
    {
        if (Victim->ZoneType == exceptionZoneIntegrity)
        {
            LOG("Victim    -> Circular Kernel Context Logger (%016llx, %016llx), "
                "WriteInfo: (%d, %016llx -> %016llx), INTEGRITY\n",
                Victim->Integrity.StartVirtualAddress,
                Victim->Integrity.StartVirtualAddress + Victim->Integrity.TotalLength,
                Victim->WriteInfo.AccessSize,
                Victim->WriteInfo.OldValue[0],
                Victim->WriteInfo.NewValue[0]);
        }
        else
        {
            LOG("Victim    -> Circular Kernel Context Logger (%016llx, %016llx), "
                "WriteInfo: (%d, %016llx -> %016llx), EPT\n",
                Victim->Ept.Gva, Victim->Ept.Gpa,
                Victim->WriteInfo.AccessSize,
                Victim->WriteInfo.OldValue[0],
                Victim->WriteInfo.NewValue[0]);
        }
    }
    else if (Victim->Object.Type == introObjectTypeHalPerfCounter)
    {
        LOG("Victim    -> HalPerformanceCounter (%016llx, %016llx), "
            "WriteInfo: (%d, %016llx -> %016llx), INTEGRITY\n",
            Victim->Integrity.StartVirtualAddress,
            Victim->Integrity.StartVirtualAddress + Victim->Integrity.TotalLength,
            Victim->WriteInfo.AccessSize,
            Victim->WriteInfo.OldValue[0],
            Victim->WriteInfo.NewValue[0]);
    }
    else if (Victim->Object.Type == introObjectTypeGdtr ||
             Victim->Object.Type == introObjectTypeIdtr)
    {
        ret = IntExceptPrintDtrInfo(Victim, "Victim    -> Dtr: ", l, rem);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeTokenPrivs)
    {
        if (Victim->ZoneType == exceptionZoneIntegrity)
        {
            LOG("Victim    -> Token privileges (%s [0x%08x] %d), WriteInfo: (Present: 0x%016llx, "
                "Enabled: 0x%016llx -> Present: 0x%016llx, Enabled: 0x%016llx), INTEGRITY\n",
                Victim->Object.WinProc->Name,
                Victim->Object.WinProc->NameHash,
                Victim->Object.WinProc->Pid,
                Victim->WriteInfo.OldValue[0],
                Victim->WriteInfo.OldValue[1],
                Victim->WriteInfo.NewValue[0],
                Victim->WriteInfo.NewValue[1]);
        }
        else
        {
            LOG("Victim    -> Token privileges (%s [0x%08x] %d), WriteInfo: (%d, %016llx -> %016llx), EPT\n",
                Victim->Object.WinProc->Name,
                Victim->Object.WinProc->NameHash,
                Victim->Object.WinProc->Pid,
                Victim->WriteInfo.AccessSize,
                Victim->WriteInfo.OldValue[0],
                Victim->WriteInfo.NewValue[0]);
        }
    }
    else if (Victim->Object.Type == introObjectTypeSecDesc ||
             Victim->Object.Type == introObjectTypeAcl)
    {
         ACL oldSacl;
         ACL oldDacl;
         ACL newSacl;
         ACL newDacl;
         DWORD SDHeadersHash = 0;

         // #ACL is exactly QWORD size, so we going to use some WriteInfo values to store the SACL and DACL.
         // For both #introObjectTypeSecDesc and #introObjectTypeAcl we store the information as follows:
         // - OldValue[0] is the old SACL
         // - NewValue[0] is the new SACL
         // - OldValue[1] is the old DACL
         // - NewValue[1] is the new DACL
         // - AccessSize is the size of the new security descriptor buffer.
         //
         // For #introObjectTypeSecDesc:
         // - OldValue[2] is the old security descriptor pointer
         // - NewValue[2] is the new security descriptor pointer

         memcpy(&oldSacl, &Victim->WriteInfo.OldValue[0], sizeof(ACL));
         memcpy(&newSacl, &Victim->WriteInfo.NewValue[0], sizeof(ACL));

         memcpy(&oldDacl, &Victim->WriteInfo.OldValue[1], sizeof(ACL));
         memcpy(&newDacl, &Victim->WriteInfo.NewValue[1], sizeof(ACL));

         if (Victim->Integrity.Buffer)
         {
             SDHeadersHash = Crc32Compute(Victim->Integrity.Buffer,
                                          Victim->Integrity.BufferSize,
                                          INITIAL_CRC_VALUE);
         }

         if (Victim->Object.Type == introObjectTypeSecDesc)
         {
             LOG("Victim    -> Security descriptor pointer was modified for process (%s [0x%08x] %d), WriteInfo: "
                 "(NewSdSize:%d, 0x%016llx -> 0x%016llx) New SD Hash:0x%x Old SACL "
                 "AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New SACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "Old DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x\n",
                 Victim->Object.WinProc->Name,
                 Victim->Object.WinProc->NameHash,
                 Victim->Object.WinProc->Pid,
                 Victim->Integrity.BufferSize,
                 Victim->WriteInfo.OldValue[2],
                 Victim->WriteInfo.NewValue[2],
                 SDHeadersHash,
                 oldSacl.AclSize, oldSacl.AceCount, oldSacl.AclRevision,
                 newSacl.AclSize, newSacl.AceCount, newSacl.AclRevision,
                 oldDacl.AclSize, oldDacl.AceCount, oldDacl.AclRevision,
                 newDacl.AclSize, newDacl.AceCount, newDacl.AclRevision);
         }
         else
         {
             LOG("Victim    -> ACL edited for process (%s [0x%08x] %d) NewSdSize:%d New SD Hash:0x%x "
                 "Old SACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New SACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "Old DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x\n",
                 Victim->Object.WinProc->Name,
                 Victim->Object.WinProc->NameHash,
                 Victim->Object.WinProc->Pid,
                 Victim->Integrity.BufferSize,
                 SDHeadersHash,
                 oldSacl.AclSize, oldSacl.AceCount, oldSacl.AclRevision,
                 newSacl.AclSize, newSacl.AceCount, newSacl.AclRevision,
                 oldDacl.AclSize, oldDacl.AceCount, oldDacl.AclRevision,
                 newDacl.AclSize, newDacl.AceCount, newDacl.AclRevision);
         }
    }
    else if (Victim->Object.Type == introObjectTypeSudIntegrity)
    {
        LOG("Victim    -> SharedUserData (%s [0x%08x] 0x%016llx + 0x%08x), WriteInfo: (0x%016llx -> 0x%016llx 0x%08x)\n",
            Victim->Object.Name,
            Victim->Object.NameHash,
            Victim->Integrity.StartVirtualAddress,
            Victim->Integrity.Offset,
            Victim->WriteInfo.OldValue[0],
            Victim->WriteInfo.NewValue[0],
            Victim->WriteInfo.AccessSize);
    }
    else if (Victim->Object.Type == introObjectTypeInterruptObject)
    {
        LOG("Victim    -> Interrupt Object (0x%016llx, entry %d) DispatchAddress: (0x%016llx -> 0x%016llx), "
            "ServiceRoutine: (0x%016llx -> 0x%016llx)",
            Victim->Integrity.StartVirtualAddress, Victim->Integrity.InterruptObjIndex,
            Victim->WriteInfo.OldValue[0], Victim->WriteInfo.NewValue[0],
            Victim->WriteInfo.OldValue[1], Victim->WriteInfo.NewValue[1]);
    }

    if (Action == introGuestNotAllowed)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = snprintf(l, rem, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%sROOTKIT (kernel-mode) ",
                       gGuest.KernelBetaDetections ? " (B) " : " ");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        switch (Reason)
        {
        case introReasonSignatureNotMatched:
            ret = snprintf(l, rem, "(no sig)");
            break;
        case introReasonNoException:
            ret = snprintf(l, rem, "(no exc)");
            break;
        case introReasonExtraChecksFailed:
            ret = snprintf(l, rem, "(extra)");
            break;
        case introReasonInternalError:
            ret = snprintf(l, rem, "(error)");
            break;
        case introReasonValueNotMatched:
            ret = snprintf(l, rem, "(value)");
            break;
        case introReasonExportNotMatched:
            ret = snprintf(l, rem, "(export)");
            break;
        case introReasonValueCodeNotMatched:
            ret = snprintf(l, rem, "(value code)");
            break;
        case introReasonIdtNotMatched:
            ret = snprintf(l, rem, "(idt)");
            break;
        case introReasonVersionOsNotMatched:
            ret = snprintf(l, rem, "(version os)");
            break;
        case introReasonVersionIntroNotMatched:
            ret = snprintf(l, rem, "(version intro)");
            break;
        case introReasonProcessCreationNotMatched:
            ret = snprintf(l, rem, "(process creation)");
            break;
        case introReasonUnknown:
            ret = snprintf(l, rem, "(unknown)");
            break;
        default:
            ret = snprintf(l, rem, "(%d)", Reason);
            break;
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n\n", gExcLogLine);
    }
    for (DWORD t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
    {
        if (NULL != Originator->StackTrace.Traces[t].ReturnModule)
        {
            LOG("[STACK TRACE] [at 0x%016llx] returning to [%s at 0x%016llx]\n",
                Originator->StackTrace.Traces[t].CurrentRip,
                utf16_for_log(((KERNEL_DRIVER *)Originator->StackTrace.Traces[t].ReturnModule)->Name),
                Originator->StackTrace.Traces[t].ReturnAddress);
        }
        else
        {
            LOG("[STACK TRACE] [at 0x%016llx]\n", Originator->StackTrace.Traces[t].CurrentRip);
        }
    }
}


void
IntExceptKernelLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a kernel-mode violation and dumps the code-blocks.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    if ((introGuestNotAllowed != Action) && (introReasonAllowedFeedback != Reason))
    {
        return;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        IntExceptKernelLogWindowsInformation(Victim, Originator, Action, Reason);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntExceptKernelLogLinuxInformation(Victim, Originator, Action, Reason);
    }

    if (!(Victim->ZoneFlags & ZONE_INTEGRITY))
    {
        IntExceptDumpSignatures(Originator, Victim, TRUE, FALSE);
        IntExceptDumpSignatures(Originator, Victim, TRUE, TRUE);
    }
}


static BOOLEAN
IntExceptLixKernelIsMemoryFunc(
    _In_ QWORD Rip
    )
///
/// @brief This function is used to check if the write has been made using any of "memcpy","__memcpy",
/// "memset", "__memset", "memmove" function.
///
/// @param[in]  Rip             The rip from which the writing came from.
///
/// @retval     True if the write has been made using the generic write functions, otherwise, false.
///
{
    for (DWORD i = 0; i < ARRAYSIZE(gLixGuest->MemoryFunctions); i++)
    {
        if (gLixGuest->MemoryFunctions[i].Start == 0 || gLixGuest->MemoryFunctions[i].End == 0)
        {
            continue;
        }

        if (Rip >= gLixGuest->MemoryFunctions[i].Start && Rip < gLixGuest->MemoryFunctions[i].End)
        {
            return TRUE;
        }
    }

    return FALSE;
}


static INTSTATUS
IntExceptLixKernelGetOriginator(
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator
    )
///
/// @brief This function is used to get the information about the kernel-mode originator (Linux guest).
///
/// The stack-trace is parsed in order to fetch the return driver.
///
/// @param[out] Originator      The originator object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS pRegs;
    KERNEL_DRIVER *pDriver;
    QWORD rip;

    pRegs = &gVcpu->Regs;
    Originator->StackTrace.Traces = Originator->StackElements;

    Originator->Original.Driver = IntDriverFindByAddress(pRegs->Rip);

    status = IntLixStackTraceGetReg(0, pRegs, ARRAYSIZE(Originator->StackElements), 0, &Originator->StackTrace);
    if (!INT_SUCCESS(status) && 0 == Originator->StackTrace.NumberOfTraces)
    {
        WARNING("[WARNING] Failed getting a stack trace: 0x%08x. Skip checking for exported functions!\n",
                status);
    }

    for (DWORD t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
    {
        KERNEL_DRIVER *pRetMod = IntDriverFindByAddress(Originator->StackTrace.Traces[t].ReturnAddress);
        if (NULL == pRetMod)
        {
            continue;
        }

        Originator->Return.Driver = pRetMod;
        Originator->Return.Rip = Originator->StackTrace.Traces[t].ReturnAddress;

        break;
    }

    if (NULL == Originator->Return.Driver)
    {
        for (DWORD t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
        {
            KERNEL_DRIVER *pRetMod = IntDriverFindByAddress(Originator->StackTrace.Traces[t].ReturnAddress);
            if (NULL == pRetMod)
            {
                continue;
            }

            // Skip mem* functions
            if (pRetMod == gGuest.KernelDriver &&
                IntExceptLixKernelIsMemoryFunc(Originator->StackTrace.Traces[t].ReturnAddress))
            {
                continue;
            }

            Originator->Return.Driver = pRetMod;
            Originator->Return.Rip = Originator->StackTrace.Traces[t].ReturnAddress;

            break;
        }
    }

    if (NULL == Originator->Original.Driver && NULL == Originator->Return.Driver)
    {
        // We have nothing to check, and we don't except this (yet?)
        return INT_STATUS_SUCCESS;
    }

    if (NULL != Originator->Original.Driver)
    {
        rip = Originator->Original.Rip;
        pDriver = Originator->Original.Driver;

        if (pDriver->BaseVa == gGuest.KernelVa)
        {
            Originator->Original.NameHash = kmExcNameKernel;
        }
        else
        {
            Originator->Original.NameHash = pDriver->NameHash;
        }

        IntLixDrvGetSecName(pDriver, rip, Originator->Original.Section);
    }
    else
    {
        Originator->Original.NameHash = INITIAL_CRC_VALUE;
    }

    if (NULL != Originator->Return.Driver)
    {
        rip = Originator->Return.Rip;
        pDriver = Originator->Return.Driver;

        if (pDriver->BaseVa == gGuest.KernelVa)
        {
            Originator->Return.NameHash = kmExcNameKernel;
        }
        else
        {
            Originator->Return.NameHash = pDriver->NameHash;
        }

        IntLixDrvGetSecName(pDriver, rip, Originator->Return.Section);
    }
    else
    {
        Originator->Return.NameHash = INITIAL_CRC_VALUE;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntExceptWinKernelGetOriginator(
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ DWORD Options
    )
///
/// @brief This function is used to get the information about the kernel-mode originator (windows guest).
///
/// The stack-trace is parsed in order to fetch the return driver.
///
/// The section for the original and the return driver is parsed in order to check if the violation should be blocked.
///
/// @param[out] Originator      The originator object.
/// @param[out] Options         A mask containing different flags regarding how the originator should be fetched.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_EXCEPTION_BLOCK     If the violation should be blocked.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver, *pOriginalDriver;

    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    DWORD currentTrace = 0;
    QWORD stackFrame = gGuest.Guest64 ? pRegs->Rsp : pRegs->Rbp;
    DWORD stackDepth;

    // Find the original driver that's modifying the memory
    Originator->Original.Driver = IntDriverFindByAddress(Originator->Original.Rip);

    stackDepth = (NULL == Originator->Original.Driver || !!(Options & EXCEPTION_KM_ORIGINATOR_OPT_FULL_STACK)) ? 3 : 1;

    // Reset the stack trace
    Originator->StackTrace.Traces = Originator->StackElements;

    status = IntWinStackTraceGet(stackFrame, pRegs->Rip, stackDepth, 0, &Originator->StackTrace);
    if (!INT_SUCCESS(status) && (Originator->StackTrace.NumberOfTraces == 0))
    {
        WARNING("[WARNING] Failed getting a stack trace: 0x%08x. Skip checking for exported functions!\n",
                status);
    }

    // This is a RIP that isn't inside any driver... We have special exceptions
    // for this case, so get the first return driver.
    if (NULL == Originator->Original.Driver)
    {
        DWORD t;

        for (t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
        {
            if (NULL == Originator->StackTrace.Traces[t].ReturnModule)
            {
                continue;
            }

            Originator->Return.Driver = Originator->StackTrace.Traces[t].ReturnModule;

            Originator->Return.Rip = Originator->StackTrace.Traces[t].ReturnAddress;

            break;
        }
    }
    else
    {
        // They are the same, unless we will found otherwise
        Originator->Return.Driver = Originator->Original.Driver;
    }

    if (NULL == Originator->Original.Driver && NULL != Originator->Return.Driver)
    {
        TRACE("[WARNING] The RIP 0x%016llx is not inside any module, but it returns to one 0x%016llx "
              "(BaseVa 0x%016llx).\n",
              Originator->Original.Rip,
              Originator->Return.Rip,
              Originator->Return.Driver->BaseVa);
    }
    else if (NULL == Originator->Original.Driver && NULL == Originator->Return.Driver)
    {
        // We have nothing to check, and we don't except this (yet?)
        Originator->Original.NameHash = INITIAL_CRC_VALUE;
        Originator->Return.NameHash = INITIAL_CRC_VALUE;
        return INT_STATUS_SUCCESS;
    }

    pDriver = Originator->Return.Driver;
    pOriginalDriver = Originator->Original.Driver;

    do
    {
        IMAGE_SECTION_HEADER sectionHeader;
        DRIVER_EXPORT_CACHE_ENTRY *pCache = NULL;

        // Get the section header for the current RIP
        status = IntPeGetSectionHeaderByRva(pDriver->BaseVa,
                                            pDriver->Win.MzPeHeaders,
                                            (DWORD)(Originator->Return.Rip - pDriver->BaseVa),
                                            &sectionHeader);
        if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
        {
            ERROR("[ERROR] Failed getting section details for Rip 0x%016llx: 0x%08x\n",
                  Originator->Original.Rip, status);
            return status;
        }
        else if (status == INT_STATUS_NOT_FOUND)
        {
            WARNING("[WARNING] Rip 0x%016llx isn't inside any section. ModuleBase: 0x%016llx\n",
                    Originator->Original.Rip, pDriver->BaseVa);
            if (0 == (Options & EXCEPTION_KM_ORIGINATOR_OPT_DO_NOT_BLOCK))
            {
                return INT_STATUS_EXCEPTION_BLOCK;
            }
            else
            {
                break;
            }
        }

        // Will only happen once
        if (Originator->Original.Driver != NULL &&
            0 == Originator->Original.Section[0])
        {
            memcpy(Originator->Original.Section, sectionHeader.Name, sizeof(sectionHeader.Name));
        }

        memcpy(Originator->Return.Section, sectionHeader.Name, sizeof(sectionHeader.Name));

        // See if this is the verifier
        if (pDriver->BaseVa == gGuest.KernelVa &&
            0 == memcmp(Originator->Return.Section, "PAGEVRF", 7))
        {
            WARNING("[WARNING] The RIP is inside the kernel section %s, the VERIFIER is active...\n",
                    Originator->Return.Section);
        }

        // See if the section is writable and not discardable or doesn't have the CODE or EXEC flags
        if (0 == (sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE) &&
            0 == (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            0 != (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            WARNING("[WARNING] Code executed from a section that doesn't contain code (RIP 0x%016llx). " \
                    "Characteristics: 0x%08x, Name: %s\n",
                    Originator->Return.Rip, sectionHeader.Characteristics, Originator->Return.Section);
            if (0 == (Options & EXCEPTION_KM_ORIGINATOR_OPT_DO_NOT_BLOCK))
            {
                return INT_STATUS_EXCEPTION_BLOCK;
            }
            else
            {
                break;
            }
        }
        if (Originator->Return.Rip - pDriver->EntryPoint < PAGE_SIZE &&
            0 == memcmp(Originator->Return.Section, "INIT", 4))
        {
            Originator->IsEntryPoint = TRUE;

            // The entry point can be exported. This ensures that it won't go further (to IopInitializeDriver & co.)
            break;
        }

        if (0 == Originator->StackTrace.NumberOfTraces ||
            NULL == Originator->Original.Driver)
        {
            // There is no point in going further
            break;
        }


        // See if this RIP is inside an exported function
        pCache = IntDriverCacheExportFind(Originator->Return.Rip);
        if (pCache == NULL)
        {
            if (pDriver->BaseVa != gGuest.KernelVa)
            {
                status = IntPeFindExportByRva(pDriver->BaseVa,
                                              pDriver->Win.MzPeHeaders,
                                              (DWORD)(Originator->Return.Rip - pDriver->BaseVa));
            }
            else
            {
                status = IntPeFindExportByRvaInBuffer(pDriver->BaseVa,
                                                      gWinGuest->KernelBuffer,
                                                      gWinGuest->KernelBufferSize,
                                                      (DWORD)(Originator->Return.Rip - pDriver->BaseVa));
            }

            if (INT_STATUS_NOT_FOUND == status)
            {
                IntDriverCacheCreateUnknown(Originator->Return.Rip);
                break;
            }
            else if (!INT_SUCCESS(status))
            {
                // Don't compare the status to specific values since on XEN it will be different.
                // If a driver is calling a function in another driver, than assume that function is exported, in case
                // we had an error, which usually happens when the export directory is paged out.
                if (pDriver == Originator->StackTrace.Traces[currentTrace].ReturnModule)
                {
                    break;
                }
            }
            else
            {
                IntDriverCacheCreateExport(Originator->Return.Rip);
            }
        }
        else
        {
            if (pCache->Type.Unknown)
            {
                break;
            }
        }

        // We are done analyzing current RIP, go further if needed
        if (NULL == Originator->StackTrace.Traces[currentTrace].ReturnModule)
        {
            WARNING("[WARNING] RIP 0x%016llx returning to an address that isn't inside a driver 0x%016llx. "
                    "Block the attempt\n",
                    Originator->Original.Rip,
                    Originator->StackTrace.Traces[currentTrace].ReturnAddress);

            if (0 == (Options & EXCEPTION_KM_ORIGINATOR_OPT_DO_NOT_BLOCK))
            {
                return INT_STATUS_EXCEPTION_BLOCK;
            }
            else
            {
                break;
            }
        }
        else
        {
            status = INT_STATUS_SUCCESS; // go to the next one
        }

        // If we had an error the we must get out now
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        // Modify the Rip and Driver to the return address and analyze that too
        Originator->Return.Rip = Originator->StackTrace.Traces[currentTrace].ReturnAddress;

        pDriver = Originator->StackTrace.Traces[currentTrace].ReturnModule;
        if (NULL == pDriver)
        {
            return INT_STATUS_NOT_FOUND;
        }

        Originator->Return.Driver = pDriver;

        currentTrace++;
    } while (currentTrace < Originator->StackTrace.NumberOfTraces);

    // Now get the hashes
    if (pDriver->BaseVa == gGuest.KernelVa)
    {
        Originator->Return.NameHash = kmExcNameKernel;
    }
    else if (0 == wstrcasecmp(pDriver->Name, u"hal.dll") ||
             0 == wstrcasecmp(pDriver->Name, u"halmacpi.dll") ||
             0 == wstrcasecmp(pDriver->Name, u"halacpi.dll"))
    {
        Originator->Return.NameHash = kmExcNameHal;
    }
    else
    {
        Originator->Return.NameHash = pDriver->NameHash;
    }

    // In case we had one (there is at least one case [virtualbox] where we don't)
    if (pOriginalDriver)
    {
        if (pOriginalDriver->BaseVa == gGuest.KernelVa)
        {
            Originator->Original.NameHash = kmExcNameKernel;
        }
        else if (0 == wstrcasecmp(pOriginalDriver->Name, u"hal.dll") ||
                 0 == wstrcasecmp(pOriginalDriver->Name, u"halmacpi.dll") ||
                 0 == wstrcasecmp(pOriginalDriver->Name, u"halacpi.dll"))
        {
            Originator->Original.NameHash = kmExcNameHal;
        }
        else
        {
            Originator->Original.NameHash = pOriginalDriver->NameHash;
        }
    }
    else
    {
        Originator->Original.NameHash = INITIAL_CRC_VALUE;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptKernelGetOriginator(
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ DWORD Options
    )
///
/// @brief This function is used to get the information about the kernel-mode originator.
///
/// @param[out] Originator      The originator object.
/// @param[out] Options         A mask containing different flags regarding how the originator should be fetched.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided originator is invalid.
/// @retval     #INT_STATUS_NOT_SUPPORTED       If the guest type is not supported.
///
{
    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // Save the original RIP; the current RIP is the same until we found otherwise
    Originator->Original.Rip = gVcpu->Regs.Rip;
    Originator->Return.Rip = gVcpu->Regs.Rip;

    if (CPU_STATE_EPT_VIOLATION == gVcpu->State || CPU_STATE_DTR_LOAD == gVcpu->State)
    {
        Originator->Instruction = &gVcpu->Instruction;
    }
    else
    {
        Originator->Instruction = NULL;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return IntExceptWinKernelGetOriginator(Originator, Options);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntExceptLixKernelGetOriginator(Originator);
    }

    return INT_STATUS_NOT_SUPPORTED;
}


INTSTATUS
IntExceptGetOriginatorFromModification(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator
    )
///
/// @brief This function is used for integrity violations to get the information about the kernel-mode originator.
///
/// The function tries to get the address of the originator driver from the written memory zone (victim->WriteInfo).
///
/// @param[in]  Victim          The victim object.
/// @param[out] Originator      The originator object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_EXCEPTION_BLOCK     If the violation should be blocked.
/// @retval     #INT_STATUS_EXCEPTION_ALLOW     If the violation should be allowed.
/// @retval     #INT_STATUS_NOT_SUPPORTED       If the modified object type is not of the following:
///                                                 - introObjectTypeDriverObject
///                                                 - introObjectTypeFastIoDispatch
///                                                 - introObjectTypeHalDispatchTable
///                                                 - introObjectTypeKmLoggerContext
///                                                 - introObjectTypeIdt
///
{
    INTSTATUS status;

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.OSType != introGuestWindows)
    {
        ERROR("[ERROR] Integrity alerts are not supported on guests %d\n", gGuest.OSType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    Originator->IsIntegrity = TRUE;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, Victim->WriteInfo.NewValue[0]) &&
        (Victim->Object.Type == introObjectTypeFastIoDispatch))
    {
        if ((gGuest.Guest64 && FIELD_OFFSET(FAST_IO_DISPATCH64, SizeOfFastIoDispatch) == Victim->Integrity.Offset) ||
            (!gGuest.Guest64 && FIELD_OFFSET(FAST_IO_DISPATCH32, SizeOfFastIoDispatch) == Victim->Integrity.Offset))
        {
            if (Victim->WriteInfo.NewValue[0] < 0x60 || Victim->WriteInfo.NewValue[0] > 0x200)
            {
                WARNING("[WARNING] The new size 0x%016llx is too big...\n", Victim->WriteInfo.NewValue[0]);
                return INT_STATUS_EXCEPTION_BLOCK;
            }

            return INT_STATUS_EXCEPTION_ALLOW;
        }

        WARNING("[WARNING] Not writing on size field & writing non-pointer value: 0x%016llx\n",
                Victim->WriteInfo.NewValue[0]);
    }

    if (Victim->Object.Type == introObjectTypeDriverObject      ||
        Victim->Object.Type == introObjectTypeFastIoDispatch    ||
        Victim->Object.Type == introObjectTypeHalDispatchTable  ||
        Victim->Object.Type == introObjectTypeKmLoggerContext   ||
        Victim->Object.Type == introObjectTypeIdt               ||
        Victim->Object.Type == introObjectTypeHalPerfCounter)
    {
        QWORD addr = 0;

        if (Victim->Object.Type == introObjectTypeIdt)
        {
            if (gGuest.Guest64)
            {
                IDT_ENTRY64 *pDescr = (IDT_ENTRY64 *)(Victim->WriteInfo.NewValue);
                addr = ((QWORD)pDescr->Offset63_32 << 32)
                    | ((pDescr->Offset31_16 << 16) & 0xFFFF0000) | pDescr->Offset15_0;
            }
            else
            {
                IDT_ENTRY32 *pDescr = (IDT_ENTRY32 *)(Victim->WriteInfo.NewValue);
                addr = ((pDescr->Offset31_16 << 16) & 0xFFFF0000) | pDescr->Offset15_0;
            }
        }
        else
        {
            addr = Victim->WriteInfo.NewValue[0];
        }

        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, addr))
        {
            Originator->Return.Driver = IntDriverFindByAddress(addr);
        }

        if (NULL == Originator->Return.Driver)
        {
            if (introObjectTypeIdt != Victim->Object.Type)
            {
                WARNING("[WARNING] Written value is not a kernel pointer or inside any driver: 0x%016llx\n", addr);
                return INT_STATUS_EXCEPTION_BLOCK;
            }

            Originator->Return.NameHash = INITIAL_CRC_VALUE;
        }
        else if (Originator->Return.Driver->BaseVa == gGuest.KernelVa)
        {
            Originator->Return.NameHash = kmExcNameKernel;
        }
        else if (0 == wstrcasecmp(Originator->Return.Driver->Name, u"hal.dll") ||
                 0 == wstrcasecmp(Originator->Return.Driver->Name, u"halmacpi.dll") ||
                 0 == wstrcasecmp(Originator->Return.Driver->Name, u"halacpi.dll"))
        {
            Originator->Return.NameHash = kmExcNameHal;
        }
        else
        {
            Originator->Return.NameHash = Originator->Return.Driver->NameHash;
        }

        // And now, copy everything into the original field too
        Originator->Original.NameHash = Originator->Return.NameHash;
        Originator->Original.Driver = Originator->Return.Driver;

        status = INT_STATUS_SUCCESS;
    }
    else if (Victim->Object.Type == introObjectTypeInterruptObject)
    {
        QWORD addr = Victim->WriteInfo.NewValue[0];

        Originator->Return.Driver = IntDriverFindByAddress(addr);

        // First we need to verify if Dispatch address points in kernel.
        if (NULL == Originator->Return.Driver)
        {
            Originator->Return.NameHash = INITIAL_CRC_VALUE;
        }
        else if (Originator->Return.Driver->BaseVa == gGuest.KernelVa)
        {
            Originator->Return.NameHash = kmExcNameKernel;
        }
        else if (0 == wstrcasecmp(Originator->Return.Driver->Name, u"hal.dll") ||
                 0 == wstrcasecmp(Originator->Return.Driver->Name, u"halmacpi.dll") ||
                 0 == wstrcasecmp(Originator->Return.Driver->Name, u"halacpi.dll"))
        {
            Originator->Return.NameHash = kmExcNameHal;
        }
        else
        {
            Originator->Return.NameHash = Originator->Return.Driver->NameHash;
        }

        if (Originator->Return.NameHash == kmExcNameKernel)
        {
            // Now fill the Original from ServiceRoutine, since the return is in the kernel.
            addr = Victim->WriteInfo.NewValue[1];

            Originator->Original.Driver = IntDriverFindByAddress(addr);

            if (NULL == Originator->Original.Driver)
            {
                Originator->Original.NameHash = INITIAL_CRC_VALUE;
            }
            else if (Originator->Original.Driver->BaseVa == gGuest.KernelVa)
            {
                Originator->Original.NameHash = kmExcNameKernel;
            }
            else if (0 == wstrcasecmp(Originator->Original.Driver->Name, u"hal.dll") ||
                     0 == wstrcasecmp(Originator->Original.Driver->Name, u"halmacpi.dll") ||
                     0 == wstrcasecmp(Originator->Original.Driver->Name, u"halacpi.dll"))
            {
                Originator->Original.NameHash = kmExcNameHal;
            }
            else
            {
                Originator->Original.NameHash = Originator->Original.Driver->NameHash;
            }
        }
        else
        {
            Originator->Original.NameHash = Originator->Return.NameHash;
            Originator->Original.Driver = Originator->Return.Driver;
        }

        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntExceptGetVictimDtr(
    _In_ DTR *NewValue,
    _In_ DTR *OldValue,
    _In_ INTRO_OBJECT_TYPE Type,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the DTR victim.
///
/// @param[in]  NewValue        The new value (written) of the DTR.
/// @param[in]  OldValue        The old value of the DTR.
/// @param[in]  Type            Any of the following: #introObjectTypeIdtr / #introObjectTypeGdtr.
/// @param[out] Victim          The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided DTR object is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 If the provided DTR object is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 If the provided victim object is invalid.
///
{
    if (NULL == NewValue)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == OldValue)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    Victim->Object.Type = Type;
    Victim->ZoneType = exceptionZoneDtr;

    Victim->WriteInfo.NewValue[0] = NewValue->Base;
    Victim->WriteInfo.NewValue[1] = NewValue->Limit;
    Victim->Dtr.Type = Type;
    Victim->WriteInfo.OldValue[0] = OldValue->Base;
    Victim->WriteInfo.OldValue[1] = OldValue->Limit;
    Victim->WriteInfo.AccessSize = gGuest.WordSize + 2;

    Victim->ZoneFlags |= ZONE_WRITE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptGetVictimMsr(
    _In_ QWORD NewValue,
    _In_ QWORD OldValue,
    _In_ DWORD Msr,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the MSR victim.
///
/// @param[in]  NewValue        The new value (written) of the MSR.
/// @param[in]  OldValue        The old value of the MSR.
/// @param[in]  Msr             The number of the MSR.
/// @param[out] Victim          The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 If the provided victim object is invalid.
///
{
    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    // Type is relevant only in EPT zone, where we don't know what zone it is. Here we know it's a MSR.
    Victim->Object.Type = 0;
    Victim->ZoneType = exceptionZoneMsr;

    Victim->WriteInfo.NewValue[0] = NewValue;
    Victim->Msr.Msr = Msr;
    Victim->WriteInfo.OldValue[0] = OldValue;
    Victim->WriteInfo.AccessSize = gGuest.WordSize;

    Victim->Msr.NewDriverBase = 0;
    Victim->ZoneFlags |= ZONE_WRITE;

    KERNEL_DRIVER *pDriver = IntDriverFindByAddress(NewValue);
    if (pDriver)
    {
        Victim->Msr.NewDriverBase = pDriver->BaseVa;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptGetVictimIntegrity(
    _In_ INTEGRITY_REGION *IntegrityRegion,
    _Inout_ DWORD *Offset,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the modified zone from the integrity region.
///
/// Will get the old value and new value at the modified address aligned down to 64/32 bits (the upper bytes may be
/// the same, so we won't catch them). Returns the found modification offset so we can call it recursively (we start
/// scanning at the given offset).
///
/// @param[in]  IntegrityRegion The integrity region object.
/// @param[in]  Offset          The offset in the region (not page) form where to search for modifications
///                                 (for recursive calls).
/// @param[out] Victim          The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided integrity-region object is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 If the provided offset pointer is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 If the provided victim object is invalid.
/// @retval     #INT_STATUS_NOT_FOUND           If no modification is found.
/// @retval     #INT_STATUS_BUFFER_OVERFLOW     If the provided region modification won't fit the modified object.
///
{
    INTSTATUS status;
    BYTE *pPage, *pOriginal;
    DWORD i;
    BOOLEAN found;

    if (NULL == IntegrityRegion)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Offset)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (gGuest.OSType != introGuestWindows)
    {
        ERROR("[ERROR] Integrity alerts are not supported on guests %d\n", gGuest.OSType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    pOriginal = IntegrityRegion->OriginalContent;
    found = FALSE;

    status = IntVirtMemMap(IntegrityRegion->Gva, IntegrityRegion->Length, gGuest.Mm.SystemCr3, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping/reading at GVA 0x%016llx, with length %x: 0x%08x\n",
              IntegrityRegion->Gva, IntegrityRegion->Length, status);
        return status;
    }

    // Search for the first modification, starting at the given offset.
    for (i = *Offset; i < IntegrityRegion->Length; i++)
    {
        if (pPage[i] != pOriginal[i])
        {
            found = TRUE;
            break;
        }
    }

    if (!found)
    {
        status = INT_STATUS_NOT_FOUND;
        *Offset = IntegrityRegion->Length;
        goto _cleanup_and_leave;
    }

    // On idt, the offset at which the write occurred must be considered the start of the entry.
    // On x64, if a write occurs, let's say, at offset 15 inside the entry, we would wrongfully
    // take the offset to be equal to entry + 8, leading to possible misleading information, and
    // if it is the last entry, the modification might be deemed "outside the integrity region",
    // which should not occur.
    switch (IntegrityRegion->Type)
    {
        case introObjectTypeIdt:
            i = ALIGN_DOWN(i, gGuest.Guest64 ? IDT_DESC_SIZE64 : IDT_DESC_SIZE32);
            break;
        default:
            i = ALIGN_DOWN(i, gGuest.WordSize);
            break;
    }

    *Offset = i + gGuest.WordSize;           // the next word

    Victim->ZoneType = exceptionZoneIntegrity;
    Victim->Object.Type = IntegrityRegion->Type;
    Victim->ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;

    Victim->Integrity.StartVirtualAddress = IntegrityRegion->Gva;
    Victim->Integrity.TotalLength = IntegrityRegion->Length;
    Victim->Integrity.Offset = i;

    switch (IntegrityRegion->Type)
    {
    case introObjectTypeIdt:
        if (gGuest.Guest64)
        {
            Victim->WriteInfo.AccessSize = sizeof(IDT_ENTRY64);
        }
        else
        {
            Victim->WriteInfo.AccessSize = sizeof(IDT_ENTRY32);
        }

        *Offset += gGuest.WordSize;
        break;

    case introObjectTypeInterruptObject:
        Victim->WriteInfo.AccessSize = 2 * gGuest.WordSize;
        break;

    default:
        Victim->WriteInfo.AccessSize = gGuest.WordSize;
        break;
    }

    // Don't exit if the access size has not filled the whole buffer. Note that for a region
    // with size 4, there might be a write at offset 1 of size gGuest.WordSize == 8. We should
    // fit in the buffer the interesting values, the ones in the integrity region which were
    // accessed at least.
    if (i + Victim->WriteInfo.AccessSize > IntegrityRegion->Length)
    {
        Victim->WriteInfo.AccessSize = IntegrityRegion->Length - i;
    }

    memcpy(Victim->WriteInfo.OldValue, pOriginal + i, Victim->WriteInfo.AccessSize);
    memcpy(Victim->WriteInfo.NewValue, pPage + i, Victim->WriteInfo.AccessSize);

    switch (IntegrityRegion->Type)
    {
    case introObjectTypeDriverObject:
    case introObjectTypeFastIoDispatch:
    {
        WIN_DRIVER_OBJECT *pDrvObj = IntegrityRegion->Context;

        if (NULL == pDrvObj)
        {
            LOG("We must have a integrity context (a driver object)\n");
            status = INT_STATUS_INVALID_INTERNAL_STATE;
            goto _cleanup_and_leave;
        }

        Victim->Object.NameHash = pDrvObj->NameHash;
        Victim->Object.DriverObject = pDrvObj;
        Victim->Object.BaseAddress = pDrvObj->DriverObjectGva;

        break;
    }
    case introObjectTypeKmLoggerContext:
    case introObjectTypeHalDispatchTable:
    case introObjectTypeHalPerfCounter:
    case introObjectTypeInterruptObject:
    {
        break;
    }
    case introObjectTypeIdt:
    {
        Victim->Object.BaseAddress = IntegrityRegion->Gva;
        break;
    }

    default:
        LOG("Invalid integrity region type: %d\n", IntegrityRegion->Type);
        break;
    }

_cleanup_and_leave:
    IntVirtMemUnmap(&pPage);

    return status;
}


INTSTATUS
IntExceptGetVictimCr(
    _In_ QWORD NewValue,
    _In_ QWORD OldValue,
    _In_ DWORD Cr,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the CR victim.
///
/// @param[in]  NewValue        The new value (written) of the CR.
/// @param[in]  OldValue        The old value of the CR.
/// @param[in]  Cr              The number of the CR register.
/// @param[out] Victim          The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_NOT_SUPPORTED       If the provided CR is not CR4.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 If the provided DTR object is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 If the provided victim object is invalid.
///
{
    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (4 != Cr)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    Victim->ZoneType = exceptionZoneCr;
    Victim->ZoneFlags |= ZONE_WRITE;
    Victim->Object.Type = (DWORD) -1;

    Victim->WriteInfo.NewValue[0] = NewValue;
    Victim->WriteInfo.OldValue[0] = OldValue;
    Victim->Cr.Cr = Cr;

    Victim->WriteInfo.AccessSize = sizeof(QWORD);

    Victim->Cr.Smap = ((OldValue & CR4_SMAP) != 0) && ((NewValue & CR4_SMAP) == 0);
    Victim->Cr.Smep = ((OldValue & CR4_SMEP) != 0) && ((NewValue & CR4_SMEP) == 0);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptKernelVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief This function is used as an extra step in exception mechanism.
///
/// @param[in]  Victim      The victim object.
/// @param[in]  Originator  The originator object.
/// @param[in]  Exception   The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_OK     On success.
///
{
    UNREFERENCED_PARAMETER(Victim);
    UNREFERENCED_PARAMETER(Originator);
    UNREFERENCED_PARAMETER(Exception);

    return INT_STATUS_EXCEPTION_CHECKS_OK;
}


INTSTATUS
IntExceptKernelMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ KM_EXCEPTION *Exception
    )
///
/// @brief This function checks if the exception matches the originator and the modified zone.
///
/// The following are verified:
///     - the zone flags
///     - the zone type
///     - the exception flags
///     - the modified name-hash
///     - the architecture flags
///     - the initialization type
///     - the system-process flags
///     - the return driver
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Exception       The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_NOT_MATCHED   If any check fails.
/// @retval     #INT_STATUS_EXCEPTION_ALLOW         If all checks have passed.
///
{
    BOOLEAN match = FALSE;

    if ((Exception->Flags & EXCEPTION_FLG_READ) &&
        (Victim->ZoneFlags & ZONE_READ))
    {
        match = TRUE;
    }

    if ((Exception->Flags & EXCEPTION_FLG_EXECUTE) &&
        (Victim->ZoneFlags & ZONE_EXECUTE))
    {
        match = TRUE;
    }

    if ((Exception->Flags & EXCEPTION_FLG_WRITE) &&
        (Victim->ZoneFlags & ZONE_WRITE))
    {
        match = TRUE;
    }

    if (!match)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if ((Exception->Flags & EXCEPTION_KM_FLG_INTEGRITY) &&
        (Victim->ZoneType != exceptionZoneIntegrity))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if ((Exception->Flags & EXCEPTION_KM_FLG_NON_DRIVER) &&
        (Originator->Original.Driver != NULL))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    match = FALSE;

    if ((Exception->Flags & EXCEPTION_FLG_32) &&
        (Exception->Flags & EXCEPTION_FLG_64))
    {
        match = TRUE;
    }
    else if ((Exception->Flags & EXCEPTION_FLG_64) &&
             gGuest.Guest64)
    {
        match = TRUE;
    }
    else if ((Exception->Flags & EXCEPTION_FLG_32) &&
             !gGuest.Guest64)
    {
        match = TRUE;
    }

    if (!match)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    match = FALSE;

    if (Exception->VictimNameHash == kmExcNameAny ||
        Exception->VictimNameHash == Victim->Object.NameHash)
    {
        match = TRUE;
    }
    else if (Exception->VictimNameHash == kmExcNameOwn)
    {
        KERNEL_DRIVER *pDriver = (Exception->Flags & EXCEPTION_KM_FLG_RETURN_DRV) ?
                                 Originator->Return.Driver : Originator->Original.Driver;

        if (pDriver && gGuest.OSType == introGuestWindows)
        {
            if (Victim->Object.Type == introObjectTypeKmModule)
            {
                match = Victim->Object.BaseAddress == pDriver->BaseVa;
            }
            else if ((Victim->Object.Type == introObjectTypeDriverObject) ||
                     (Victim->Object.Type == introObjectTypeFastIoDispatch))
            {
                // Do this check, since some drivers don't have a DriverObject
                if (Victim->Object.DriverObject && pDriver->Win.DriverObject)
                {
                    // Also, check by Gpa since a driver object may be pointed from different Gva
                    match = Victim->Object.DriverObject->DriverObjectGpa == pDriver->Win.DriverObject->DriverObjectGpa;
                }
            }
        }
        else if (pDriver && gGuest.OSType == introGuestLinux)
        {
            if (Victim->Object.Type == introObjectTypeKmModule)
            {
                match = Victim->Object.BaseAddress == pDriver->Lix.CoreLayout.Base;
            }
        }
    }

    if (!match)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    match = FALSE;

    switch (Exception->Type)
    {
    case kmObjAny:
        match = TRUE;
        break;

    case kmObjDriver:
        if (Victim->Object.Type == introObjectTypeKmModule)
        {
            match = TRUE;
        }
        break;

    case kmObjDriverImports:
        if ((Victim->Object.Type == introObjectTypeKmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_IMPORTS))
        {
            match = TRUE;
        }
        break;

    case kmObjDriverExports:
        if ((Victim->Object.Type == introObjectTypeKmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_EXPORTS))
        {
            match = TRUE;
        }
        break;

    case kmObjDriverCode:
        if ((Victim->Object.Type == introObjectTypeKmModule &&
             (Victim->ZoneFlags & ZONE_LIB_CODE)) ||
            Victim->Object.Type == introObjectTypeVsyscall ||
            Victim->Object.Type == introObjectTypeVdso)
        {
            match = TRUE;
        }
        break;

    case kmObjDriverData:
        if ((Victim->Object.Type == introObjectTypeKmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_DATA))
        {
            match = TRUE;
        }
        break;

    case kmObjDriverResources:
        if ((Victim->Object.Type == introObjectTypeKmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_RESOURCES))
        {
            match = TRUE;
        }
        break;

    case kmObjSsdt:
        if (Victim->Object.Type == introObjectTypeSsdt)
        {
            match = TRUE;
        }
        break;

    case kmObjDrvObj:
        if (Victim->Object.Type == introObjectTypeDriverObject)
        {
            match = TRUE;
        }
        break;

    case kmObjFastIo:
        if (Victim->Object.Type == introObjectTypeFastIoDispatch)
        {
            match = TRUE;
        }
        break;

    case kmObjMsr:
        if (Victim->ZoneType == exceptionZoneMsr)
        {
            match = TRUE;
        }
        break;

    case kmObjCr4:
        if (Victim->ZoneType == exceptionZoneCr)
        {
            match = TRUE;
        }
        break;

    case kmObjHalHeap:
        if ((Victim->ZoneType == exceptionZoneEpt) &&
            ((Victim->Object.Type == introObjectTypeHalIntController) ||
            (Victim->Object.Type == introObjectTypeHalHeap)))
        {
            match = TRUE;
        }
        break;

    case kmObjSudExec:
        if ((Victim->ZoneType == exceptionZoneEpt) &&
            (Victim->Object.Type == introObjectTypeSudExec))
        {
            match = TRUE;
        }
        break;

    case kmObjSelfMapEntry:
        if ((Victim->ZoneType == exceptionZoneEpt) &&
            (Victim->Object.Type == introObjectTypeSelfMapEntry))
        {
            match = TRUE;
        }
        break;

    case kmObjIdt:
        if ((Victim->ZoneType == exceptionZoneEpt ||
             Victim->ZoneType == exceptionZoneIntegrity) &&
            Victim->Object.Type == introObjectTypeIdt)
        {
            match = TRUE;
        }
        break;

    case kmObjIdtr:
        if ((Victim->ZoneType == exceptionZoneDtr) &&
            (Victim->Object.Type == introObjectTypeIdtr))
        {
            match = TRUE;
        }
        break;

    case kmObjGdtr:
        if ((Victim->ZoneType == exceptionZoneDtr) &&
            (Victim->Object.Type == introObjectTypeGdtr))
        {
            match = TRUE;
        }
        break;

    case kmObjLoggerCtx:
        if (Victim->Object.Type == introObjectTypeKmLoggerContext)
        {
            match = TRUE;
        }
        break;

    case kmObjTokenPrivs:
        if (Victim->Object.Type == introObjectTypeTokenPrivs)
        {
            match = TRUE;
        }
        break;

    case kmObjHalPerfCnt:
        if (Victim->Object.Type == introObjectTypeHalPerfCounter)
        {
            match = TRUE;
        }
        break;

    case kmObjSecDesc:
        if (Victim->Object.Type == introObjectTypeSecDesc)
        {
            match = TRUE;
        }
        break;

    case kmObjAcl:
        if (Victim->Object.Type == introObjectTypeAcl)
        {
            match = TRUE;
        }
        break;

    case kmObjSudModification:
        if (Victim->Object.Type == introObjectTypeSudIntegrity)
        {
            match = TRUE;
        }
        break;

    case kmObjInterruptObject:
        if (Victim->Object.Type == introObjectTypeInterruptObject)
        {
            match = TRUE;
        }
        break;

    default:
        LOG("[ERROR] This is a corruption in the update/exception. Type = %d!\n", Exception->Type);
        break;
    }

    if (!match)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (Exception->Flags & EXCEPTION_FLG_INIT)
    {
        match = FALSE;

        // a. On integrity zones, this is all we can check
        if ((Victim->ZoneType == exceptionZoneIntegrity) &&
            (Victim->WriteInfo.OldValue[0] == 0))
        {
            match = TRUE;
        }
        // b. Kernel's INIT section writes
        else if ((Exception->Flags & EXCEPTION_KM_FLG_RETURN_DRV) &&
                 (Originator->Return.NameHash == kmExcNameKernel))
        {
            // match anything that starts with init/INIT
            if (gGuest.OSType == introGuestWindows)
            {
                match = 0 == memcmp(Originator->Return.Section, "INIT", 4);
            }
            else
            {
                match = 0 == memcmp(Originator->Return.Section, "init", 4);
            }
        }
        else if (Originator->Original.NameHash == kmExcNameKernel)
        {
            // match anything that starts with init/INIT
            if (gGuest.OSType == introGuestWindows)
            {
                match = 0 == memcmp(Originator->Original.Section, "INIT", 4);
            }
            else
            {
                match = 0 == memcmp(Originator->Original.Section, "init", 4);
            }
        }
        // c. RIP is in EntryPoint
        else if (Originator->IsEntryPoint)
        {
            match = TRUE;
        }
        // d. Old value was 0
        else if (Victim->WriteInfo.OldValue[0] == 0)
        {
            match = TRUE;
        }

        if (!match)
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
    }

    if (kmObjCr4 == Exception->Type)
    {
        // We don't care about the activation of these flags (we allow it). But the deactivation is another story...
        match = FALSE;

        if ((Exception->Flags & EXCEPTION_KM_FLG_SMAP) &&
            (Exception->Flags & EXCEPTION_KM_FLG_SMEP))
        {
            match = TRUE;
        }
        else if ((Exception->Flags & EXCEPTION_KM_FLG_SMAP) &&
                 (Victim->Cr.Smap))
        {
            match = TRUE;
        }
        else if ((Exception->Flags & EXCEPTION_KM_FLG_SMEP) &&
                 Victim->Cr.Smep)
        {
            match = TRUE;
        }

        if (!match)
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
    }

    // If we get here, then allow the action. Anyway, the extra checks & signatures mechanism will actually allow it
    return INT_STATUS_EXCEPTION_ALLOW;
}


INTSTATUS
IntExceptKernel(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief This function iterates through exception lists and tries to find an exception that matches the originator
/// and the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[out] Action          The action that was taken.
/// @param[out] Reason          The reason for which Action was taken.
///
/// @retval #INT_STATUS_INVALID_PARAMETER_1     If the victim object is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_2     If the originator object is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_3     If the action is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_4     If the reason is invalid.
/// @retval #INT_STATUS_EXCEPTION_ALLOW         If the violation is allowed.
/// @retval #INT_STATUS_EXCEPTION_NOT_MATCHED   If the violation is not allowed.
///
{
    INTSTATUS status = INT_STATUS_EXCEPTION_NOT_MATCHED;
    BOOLEAN sameRip = FALSE;
    BYTE id;

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Reason)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *Action = introGuestNotAllowed;
    *Reason = introReasonNoException;

    // In some cases the Old/New values are the same - allow them by default.
    if (__unlikely(Victim->ZoneType == exceptionZoneEpt && !!(Victim->ZoneFlags & ZONE_WRITE) &&
        !memcmp(Victim->WriteInfo.OldValue, Victim->WriteInfo.NewValue,
                MIN(Victim->WriteInfo.AccessSize, sizeof(Victim->WriteInfo.NewValue)))))
    {
        *Action = introGuestAllowed;
        *Reason = introReasonSameValue;

        return INT_STATUS_EXCEPTION_ALLOW;
    }

    for_each_km_exception(gGuest.Exceptions->KernelAlertExceptions, pEx)
    {
        if (pEx->OriginatorNameHash == kmExcNameAny)
        {
            // For now, we do not support exceptions from the alert that has originator kmExcNameAny.
            // If an exception from the alert has no originator, kmExcNameNone will be used as the exception originator
            goto _match_ex_alert;
        }

        if (Originator->Original.NameHash == INITIAL_CRC_VALUE && pEx->OriginatorNameHash == kmExcNameNone)
        {
            goto _match_ex_alert;
        }

        if (pEx->OriginatorNameHash > Originator->Original.NameHash)
        {
            break;
        }
        else if (pEx->OriginatorNameHash != Originator->Original.NameHash)
        {
            continue;
        }

_match_ex_alert:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    if (Originator->Original.NameHash == INITIAL_CRC_VALUE)
    {
        // Check the no name exceptions, and skip the generic ones
        for_each_km_exception(gGuest.Exceptions->NoNameKernelExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }
    else
    {
        // Check the generic exceptions (all of them, since originator matches anything)
        for_each_km_exception(gGuest.Exceptions->GenericKernelExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

    if (Originator->Original.Driver && Originator->Return.Driver &&
        (Originator->Original.Rip == Originator->Return.Rip))
    {
        // Don't check by RIP since it may be in different sections
        sameRip = TRUE;
    }

    if (Originator->Original.NameHash != INITIAL_CRC_VALUE)
    {
        id = EXCEPTION_TABLE_ID(Originator->Original.NameHash);

        for_each_km_exception(gGuest.Exceptions->KernelExceptions[id], pEx)
        {
            // Here we only check exceptions by the name, so that cannot be missing.
            // And the return flag must be missing.
            if (pEx->OriginatorNameHash == INITIAL_CRC_VALUE ||
                ((pEx->Flags & EXCEPTION_KM_FLG_RETURN_DRV) &&
                 !sameRip))
            {
                continue;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->OriginatorNameHash > Originator->Original.NameHash)
            {
                break;
            }
            else if (pEx->OriginatorNameHash != Originator->Original.NameHash)
            {
                continue;
            }

            // The EXCEPTION_KM_FLG_RETURN_DRV will be deleted, so do the same verification again
            if ((pEx->Flags & EXCEPTION_FLG_RETURN) && !sameRip)
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }

        if (sameRip)
        {
            // No point in doing the same thing again
            goto _beta_exceptions;
        }
    }

    // Try and match the original driver by name
    if (Originator->Return.NameHash != INITIAL_CRC_VALUE)
    {
        id = EXCEPTION_TABLE_ID(Originator->Return.NameHash);
        for_each_km_exception(gGuest.Exceptions->KernelExceptions[id], pEx)
        {
            // Here we only check exceptions by the name, so that cannot be missing
            // And the return flag must be set
            if (pEx->OriginatorNameHash == INITIAL_CRC_VALUE ||
                (0 == (pEx->Flags & EXCEPTION_KM_FLG_RETURN_DRV)))
            {
                continue;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->OriginatorNameHash > Originator->Return.NameHash)
            {
                break;
            }
            else if (pEx->OriginatorNameHash != Originator->Return.NameHash)
            {
                continue;
            }

            // The EXCEPTION_KM_FLG_RETURN_DRV will be deleted, so do the same verification again
            if (0 == (pEx->Flags & EXCEPTION_FLG_RETURN))
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

_beta_exceptions:
    for_each_km_exception(gGuest.Exceptions->KernelFeedbackExceptions, pEx)
    {
        if (pEx->OriginatorNameHash == kmExcNameAny)
        {
            goto _match_ex;
        }

        if (Originator->Original.NameHash == INITIAL_CRC_VALUE && pEx->OriginatorNameHash == kmExcNameNone)
        {
            goto _match_ex;
        }

        if (pEx->Flags & EXCEPTION_FLG_RETURN)
        {
            if (pEx->OriginatorNameHash != Originator->Return.NameHash)
            {
                continue;
            }
        }
        else
        {
            if (pEx->OriginatorNameHash != Originator->Original.NameHash)
            {
                continue;
            }
        }
_match_ex:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    return status;
}
