/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcpu.h"
#include "guests.h"
#include "lixprocess.h"
#include "winprocesshp.h"


INTSTATUS
IntEferRead(
    _In_ QWORD CpuNumber,
    _Out_ QWORD *Efer
    )
///
/// @brief      Reads the value of the guest IA32 EFER MSR
///
/// @param[in]  CpuNumber   The CPU from which the MSR is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Efer        On success, the value of the MSR
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Efer is NULL
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (NULL == Efer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    readMsr.MsrId = IG_IA32_EFER;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *Efer = readMsr.Value;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntRipRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Rip
    )
///
/// @brief      Reads the value of the guest RIP
///
/// If CpuNumber points to the current CPU and the value is already known and cached inside #gVcpu, it is not re-read
/// from the guest, and the cached value is returned, as it can not change while introcore is handling an event
/// because the guest is not running on that CPU. The value can change only by using #IntSetGprs, but in that case
/// the cached value is updated.
///
/// @param[in]  CpuNumber   The CPU from which the RIP is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Rip         On success, the value the Rip register
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Rip is NULL
///
{
    if (Rip == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if (__likely((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber)))
    {
        *Rip = gVcpu->Regs.Rip;
    }
    else
    {
        IG_ARCH_REGS regs;
        INTSTATUS status;

        status = IntGetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] : IntGetGprs, status = 0x%08x\n", status);
            return status;
        }

        *Rip = regs.Rip;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIdtFindBase(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Base,
    _Out_opt_ WORD *Limit
    )
///
/// @brief      Returns the IDT base and limit for a guest CPU
///
/// @param[in]  CpuNumber   The CPU from which the IDT is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Base     On success, the base of the IDT
/// @param[out] Limit    On success, the limit of the IDT. May be NULL
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Base is NULL
///
{
    INTSTATUS status;
    IG_ARCH_REGS regs;

    if (Base == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntGetAllRegisters(CpuNumber, &regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetAllRegisters failed: 0x%08x\n", status);
        return status;
    }

    *Base = regs.IdtBase;

    if (NULL != Limit)
    {
        *Limit = (WORD)regs.IdtLimit;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIdtGetEntry(
    _In_ DWORD CpuNumber,
    _In_ DWORD Entry,
    _Out_ QWORD *Handler
    )
///
/// @brief      Get the handler of an interrupt from the IDT
///
/// @param[in]  CpuNumber   The CPU from which the query is done. Can be #IG_CURRENT_VCPU for this CPU
/// @param[in]  Entry       The number of the IDT entry
/// @param[out] Handler     On success, the address of the interrupt handler
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Handler is NULL
///
{
    INTSTATUS status;
    QWORD idtBase = 0;

    if (Handler == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    status = IntIdtFindBase(CpuNumber, &idtBase, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIdtFindBase failed: 0x%08x\n", status);
        return status;
    }

    if (gGuest.Guest64)
    {
        INTERRUPT_GATE gate;

        status = IntKernVirtMemRead(idtBase + Entry * sizeof(gate), sizeof(gate), &gate, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *Handler = ((QWORD) gate.Offset_63_32 << 32) | ((QWORD) gate.Offset_31_16 << 16) | ((QWORD) gate.Offset_15_0);
    }
    else
    {
        INTERRUPT_GATE32 gate;

        status = IntKernVirtMemRead(idtBase + Entry * sizeof(gate), sizeof(gate), &gate, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *Handler = ((QWORD) gate.Offset_31_16 << 16) | ((QWORD) gate.Offset_15_0);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGdtFindBase(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *GdtBase,
    _Out_opt_ WORD *GdtLimit
    )
///
/// @brief      Returns the GDT base and limit for a guest CPU
///
/// @param[in]  CpuNumber   The CPU from which the GDT is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] GdtBase     On success, the base of the GDT
/// @param[out] GdtLimit    On success, the limit of the GDT. May be NULL
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if GdtBase is NULL
///
{
    INTSTATUS status;
    IG_ARCH_REGS regs;

    if (GdtBase == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_REGISTER_STATE,
                               (void *)(size_t)CpuNumber,
                               &regs,
                               sizeof(IG_ARCH_REGS));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] : IntQueryGuestInfo failed for IG_QUERY_INFO_CLASS_REGISTER_STATE, status = 0x%08x\n", status);
        return status;
    }

    *GdtBase = regs.GdtBase;

    if (NULL != GdtLimit)
    {
        *GdtLimit = (WORD)regs.GdtLimit;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntFsRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *FsValue
    )
///
/// @brief      Reads the IA32_FS_BASE guest MSR
///
/// @param[in]  CpuNumber   The CPU from which the MSR is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] FsValue     On success, the value of the MSR
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if FsValue is NULL
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (FsValue == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    readMsr.MsrId = IG_IA32_FS_BASE;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *FsValue = readMsr.Value;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGsRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *GsValue
    )
///
/// @brief      Reads the IA32_GS_BASE guest MSR
///
/// @param[in]  CpuNumber   The CPU from which the MSR is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] GsValue     On success, the value of the MSR
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if GsValue is NULL
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (GsValue == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    readMsr.MsrId = IG_IA32_GS_BASE;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *GsValue = readMsr.Value;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKernelGsRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *GsValue
    )
///
/// @brief      Reads the IA32_KERNEL_GS_BASE guest MSR
///
/// @param[in]  CpuNumber   The CPU from which the MSR is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] GsValue     On success, the value of the MSR
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if GsValue is NULL
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = { 0 };

    if (GsValue == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    readMsr.MsrId = IG_IA32_KERNEL_GS_BASE;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *GsValue = readMsr.Value;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCr0Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr0Value
    )
///
/// @brief      Reads the value of the guest CR0
///
/// If CpuNumber points to the current CPU and the value is already known and cached inside #gVcpu, it is not re-read
/// from the guest, and the cached value is returned, as it can not change while introcore is handling an event
/// because the guest is not running on that CPU. The value can not change by using #IntSetGprs.
///
/// @param[in]  CpuNumber   The CPU from which the CR0 is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Cr0Value    On success, the value the CR0 register
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Cr0Value is NULL
///
{
    if (Cr0Value == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if ((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber))
    {
        *Cr0Value = gVcpu->Regs.Cr0;
    }
    else
    {
        IG_ARCH_REGS regs;
        INTSTATUS status;

        status = IntGetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        *Cr0Value = regs.Cr0;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCr3Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr3Value
    )
///
/// @brief      Reads the value of the guest CR3
///
/// If CpuNumber points to the current CPU and the value is already known and cached inside #gVcpu, it is not re-read
/// from the guest, and the cached value is returned, as it can not change while Introcore is handling an event
/// because the guest is not running on that CPU. The value can not change by using #IntSetGprs.
///
/// @param[in]  CpuNumber   The CPU from which the CR3 is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Cr3Value    On success, the value the CR3 register
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Cr3Value is NULL
///
{
    if (Cr3Value == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if (__likely((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber)))
    {
        *Cr3Value = gVcpu->Regs.Cr3;
    }
    else
    {
        IG_ARCH_REGS regs;
        INTSTATUS status;

        status = IntGetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        *Cr3Value = regs.Cr3;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCr4Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr4Value
    )
///
/// @brief      Reads the value of the guest CR4
///
/// If CpuNumber points to the current CPU and the value is already known and cached inside #gVcpu, it is not re-read
/// from the guest, and the cached value is returned, as it can not change while introcore is handling an event
/// because the guest is not running on that CPU. The value can not change by using #IntSetGprs.
///
/// @param[in]  CpuNumber   The CPU from which the CR4 is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Cr4Value    On success, the value the CR4 register
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Cr4Value is NULL
///
{
    if (Cr4Value == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if (__likely((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber)))
    {
        *Cr4Value = gVcpu->Regs.Cr4;
    }
    else
    {
        IG_ARCH_REGS regs;
        INTSTATUS status;

        status = IntGetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        *Cr4Value = regs.Cr4;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCr8Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr8Value
    )
///
/// @brief      Reads the value of the guest CR8
///
/// If CpuNumber points to the current CPU and the value is already known and cached inside #gVcpu, it is not re-read
/// from the guest, and the cached value is returned, as it can not change while introcore is handling an event
/// because the guest is not running on that CPU. The value can not change by using #IntSetGprs.
///
/// @param[in]  CpuNumber   The CPU from which the CR8 is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Cr8Value    On success, the value the CR8 register
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Cr8Value is NULL
///
{
    if (Cr8Value == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if ((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber))
    {
        *Cr8Value = gVcpu->Regs.Cr8;
    }
    else
    {
        IG_ARCH_REGS regs;
        INTSTATUS status;

        status = IntGetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        *Cr8Value = regs.Cr8;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSysenterRead(
    _In_ DWORD CpuNumber,
    _Out_opt_ QWORD *SysCs,
    _Out_opt_ QWORD *SysEip,
    _Out_opt_ QWORD *SysEsp
    )
///
/// @brief      Queries the IA32_SYSENTER_CS, IA32_SYSENTER_EIP, and IA32_SYSENTER_ESP guest MSRs
///
/// @param[in]  CpuNumber   The CPU from which the MSRs are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] SysCs       On success, the value of the IA32_SYSENTER_CS MSR. May be NULL
/// @param[out] SysEip      On success, the value of the IA32_SYSENTER_EIP MSR. May be NULL
/// @param[out] SysEsp      On success, the value of the IA32_SYSENTER_ESP MSR. May be NULL
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (SysCs != NULL)
    {
        readMsr.MsrId = IG_IA32_SYSENTER_CS;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *SysCs = readMsr.Value;
    }

    if (SysEip != NULL)
    {
        readMsr.MsrId = IG_IA32_SYSENTER_EIP;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *SysEip = readMsr.Value;
    }

    if (SysEsp != NULL)
    {
        readMsr.MsrId = IG_IA32_SYSENTER_ESP;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *SysEsp = readMsr.Value;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSyscallRead(
    _In_ DWORD CpuNumber,
    _Out_opt_ QWORD *SysStar,
    _Out_opt_ QWORD *SysLstar
    )
///
/// @brief      Queries the IA32_STAR, and IA32_LSTAR guest MSRs
///
/// @param[in]  CpuNumber   The CPU from which the MSRs are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] SysStar     On success, the value of the IA32_STAR MSR. May be NULL.
/// @param[out] SysLstar    On success, the value of the IA32_LSTAR_MSR. May be NULL.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (SysStar != NULL)
    {
        readMsr.MsrId = IG_IA32_STAR;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *SysStar = readMsr.Value;
    }

    if (SysLstar != NULL)
    {
        readMsr.MsrId = IG_IA32_LSTAR;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *SysLstar = readMsr.Value;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDebugCtlRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *DebugCtl
    )
///
/// @brief      Queries the IA32_DEBUGCTL guest MSR
///
/// @param[in]  CpuNumber   The CPU from which the MSR is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] DebugCtl    On success, the value of the IA32_DEBUGCTL MSR. May be NULL.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    IG_QUERY_MSR readMsr = {0};

    if (DebugCtl == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    readMsr.MsrId = IG_IA32_DEBUGCTL;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR, (void *)(size_t)CpuNumber, &readMsr, sizeof(readMsr));
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *DebugCtl = readMsr.Value;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLbrRead(
    _In_ DWORD BuffersSize,
    _Out_writes_(BuffersSize) QWORD *LbrFrom,
    _Out_writes_(BuffersSize) QWORD *LbrTo
    )
///
/// @deprecated This function is no longer used
///
{
    QWORD msrLbrTos, i;

    const DWORD cFrom[LBR_STACK_SIZE] =
    {
        MSR_LBR_0_FROM_IP, MSR_LBR_1_FROM_IP, MSR_LBR_2_FROM_IP, MSR_LBR_3_FROM_IP,
        MSR_LBR_4_FROM_IP, MSR_LBR_5_FROM_IP, MSR_LBR_6_FROM_IP, MSR_LBR_7_FROM_IP,
        MSR_LBR_8_FROM_IP, MSR_LBR_9_FROM_IP, MSR_LBR_A_FROM_IP, MSR_LBR_B_FROM_IP,
        MSR_LBR_C_FROM_IP, MSR_LBR_D_FROM_IP, MSR_LBR_E_FROM_IP, MSR_LBR_F_FROM_IP,
    };

    const DWORD cTo[LBR_STACK_SIZE] =
    {
        MSR_LBR_0_TO_IP, MSR_LBR_1_TO_IP, MSR_LBR_2_TO_IP, MSR_LBR_3_TO_IP,
        MSR_LBR_4_TO_IP, MSR_LBR_5_TO_IP, MSR_LBR_6_TO_IP, MSR_LBR_7_TO_IP,
        MSR_LBR_8_TO_IP, MSR_LBR_9_TO_IP, MSR_LBR_A_TO_IP, MSR_LBR_B_TO_IP,
        MSR_LBR_C_TO_IP, MSR_LBR_D_TO_IP, MSR_LBR_E_TO_IP, MSR_LBR_F_TO_IP,
    };

    if (BuffersSize == 0)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    if (LbrFrom == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (LbrTo == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    msrLbrTos = __readmsr(IG_IA32_LBR_TOS);

    for (i = 0; i < LBR_STACK_SIZE && i < BuffersSize; i++)
    {
        LbrFrom[i] = __readmsr(cFrom[msrLbrTos]);
        LbrTo[i] = __readmsr(cTo[msrLbrTos]);
        msrLbrTos = (msrLbrTos + 1) % LBR_STACK_SIZE;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLerRead(
    _Out_ QWORD *LerFrom,
    _Out_ QWORD *LerTo
    )
///
/// @deprecated This function is no longer used
///
{
    if (LerFrom == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (LerTo == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    *LerFrom = __readmsr(MSR_LER_FROM_IP);
    *LerTo = __readmsr(MSR_LER_TO_IP);

    return INT_STATUS_SUCCESS;
}


DWORD
IntGetCurrentCpu(
    void
    )
///
/// @brief      Returns the current CPU number
///
/// @returns    The number of the current CPU
///
/// @remarks    If this function fails, it will bugcheck.
///
{
    INTSTATUS status;
    DWORD cpuNumber = 0;

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_CURRENT_TID, NULL, &cpuNumber, sizeof(DWORD));
    if (!INT_SUCCESS(status))
    {
        IntBugCheck();
    }

    return cpuNumber;
}


INTSTATUS
IntGetGprs(
    _In_ DWORD CpuNumber,
    _Out_ PIG_ARCH_REGS Regs
    )
///
/// @brief      Get the current guest GPR state
///
/// If CpuNumber points to the current CPU and the GPR values are already known and cached inside #gVcpu, we will not
/// query them again, and the cached values are returned, as they can not change while introcore is handling an event
/// because the guest is not running on that CPU. The values can change only by using #IntSetGprs, but in that case
/// the cached values are updated. In cases in which the query is done while in an user mode context, and KPTI is
/// enabled, the CR3 value returned in Regs will be that of the kernel CR3 of the current process.
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Regs        On success, will contain the values of the GPRs
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    PIG_ARCH_REGS pRegs = Regs;

    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if (__likely(CpuNumber == gVcpu->Index))
    {
        pRegs = &gVcpu->Regs;
    }

    if (__likely((CpuNumber != gVcpu->Index) || (gVcpu->EventId != gEventId)))
    {
        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS,
                                   (void *)(size_t)CpuNumber,
                                   (PBYTE)pRegs,
                                   sizeof(*pRegs));
        if (!INT_SUCCESS(status))
        {
            CRITICAL("[ERROR] IntQueryGuestInfo failed: 0x%08x\n", status);
            IntBugCheck();
        }

        if (CpuNumber == gVcpu->Index)
        {
            gVcpu->EventId = gEventId;
        }

    }

    // If this is probably a user CR3, load the kernel CR3 in our cache.
    if (__likely(gGuest.KptiActive))
    {
        if (introGuestWindows == gGuest.OSType)
        {
            PWIN_PROCESS_OBJECT pProc = IntWinProcFindObjectByUserCr3(pRegs->Cr3);
            if (NULL != pProc)
            {
                pRegs->Cr3 = pProc->Cr3;
            }
        }
        else if (__likely(introGuestLinux == gGuest.OSType))
        {
            pRegs->Cr3 = IntLixGetKernelCr3(pRegs->Cr3);
        }
    }

    if (__unlikely(Regs != pRegs))
    {
        memcpy(Regs, pRegs, sizeof(*Regs));
    }

    return status;
}


INTSTATUS
IntSetGprs(
    _In_ DWORD CpuNumber,
    _In_ PIG_ARCH_REGS Regs
    )
///
/// @brief      Sets the values of the guest GPRs
///
/// This will set only the general purpose registers (from RAX to R15), the other fields of the #IG_ARCH_REGS struct
/// are ignored. If CpuNumber points to the current CPU and the GPR values are cached inside #gVcpu, we will also
/// update the cache. If we are on an event triggered by the \#VE agent (#gVcpu->VeContext is True), the guest
/// register state will not actually change, only the values in the cache. The values will be propagated back to the
/// guest via the \#VE info page, so we'd rather avoid an expensive hypercall. If we are in the context of the \#VE
/// agent, but there is no valid register cache, Introcore will bug check, as that is an unrecoverable error.
///
/// @param[in]  CpuNumber   The CPU for which the registers are set. Can be #IG_CURRENT_VCPU for this CPU
/// @param[in]  Regs        The new register values
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    if (IG_CURRENT_VCPU == CpuNumber)
    {
        CpuNumber = gVcpu->Index;
    }

    if (__unlikely(Regs != &gVcpu->Regs))
    {
        if (__likely((gVcpu->EventId == gEventId) && (gVcpu->Index == CpuNumber)))
        {
            memcpy(&gVcpu->Regs, Regs, sizeof(*Regs));
        }
        else if (__unlikely(gVcpu->VeContext))
        {
            ERROR("[ERROR] Modifying the GPRs from #VE context, but the registers are not cached!\n");
            IntEnterDebugger();
        }
    }

    // DO NOT modify the registers if we're in #VE context. They will be propagated back inside the #VE info page
    // without the need of a costly hypercall. If the registers cache is not set for the current VCPU (see the above
    // else branch), we will cause a bug-check, as that is not normal.
    if (gVcpu->VeContext)
    {
        return INT_STATUS_SUCCESS;
    }

    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_SET_REGISTERS,
                             (void *)(size_t)CpuNumber,
                             (PBYTE)Regs,
                             sizeof(IG_ARCH_REGS));
}


INTSTATUS
IntGetCurrentRing(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *Ring
    )
///
/// @brief      Read the current protection level
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Ring        The current protection level. Can be one of the #IG_CS_RING values
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_CS_RING, (void *)(size_t)CpuNumber, (PBYTE)Ring, sizeof(DWORD));
}


INTSTATUS
IntGetCurrentMode(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *Mode
    )
///
/// @brief      Read the current CS type
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Mode        The current CS type. Can be one of the #IG_CS_TYPE values
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_CS_TYPE, (void *)(size_t)CpuNumber, (PBYTE)Mode, sizeof(DWORD));
}


INTSTATUS
IntGetSegs(
    _In_ DWORD CpuNumber,
    _Out_ PIG_SEG_REGS Regs
    )
///
/// @brief      Read the guest segment registers
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Regs        The values of the guest segment registers
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_SEG_REGISTERS, (void *)(size_t)CpuNumber, (PBYTE)Regs,
                             sizeof(IG_SEG_REGS));
}


INTSTATUS
IntGetXsaveAreaSize(
    _Out_ DWORD *Size
    )
///
/// @brief      Get the size of the guest XSAVE area on the current CPU
///
/// @param[out] Size    On success, the size of the guest XSAVE area
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_XSAVE_SIZE, (void *)(SIZE_T)IG_CURRENT_VCPU, Size, sizeof(*Size));
}


INTSTATUS
IntGetXcr0(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Xcr0Value
    )
///
/// @brief      Get the value of the guest XCR0 register
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Xcr0Value   On success, the value of the XCR0 register
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_GET_XCR0, (void *)(SIZE_T)CpuNumber, (PBYTE)Xcr0Value, sizeof(QWORD));
}


INTSTATUS
IntGetXsaveArea(
    _In_ DWORD CpuNumber,
    _Out_ XSAVE_AREA *XsaveArea
    )
///
/// @brief      Get the contents of the guest XSAVE area
///
/// The #XSAVE_AREA.XsaveArea buffer is allocated here and will be exactly #XSAVE_AREA.Size bytes in length. Callers
/// must free this buffer by calling #IntFreeXsaveArea. If the function fails, no memory is allocated.
///
/// @param[in]  CpuNumber   The CPU from which the registers are read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] XsaveArea   The XSAVE area size and contents
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES is not enough memory is available
///
{
    DWORD size = 0;
    INTSTATUS status;
    IG_XSAVE_AREA *xsave;

    status = IntGetXsaveAreaSize(&size);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetXsaveAreaSize failed: 0x%08x\n", status);
        return status;
    }

    // Right here, we can trust the size value returned by the HV.
    xsave = HpAllocWithTag(size, IC_TAG_XSAVE);
    if (NULL == xsave)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_XSAVE_AREA, (void *)(SIZE_T)CpuNumber, (BYTE *)xsave, size);
    if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&xsave, IC_TAG_XSAVE);
        return status;
    }

    XsaveArea->Size = size;
    XsaveArea->XsaveArea = xsave;
    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSetXsaveArea(
    _In_ DWORD CpuNumber,
    _In_ XSAVE_AREA *XsaveArea
    )
///
/// @brief      Sets the contents of the guest XSAVE area
///
/// @param[in]  CpuNumber   The CPU on which the XSAVE area contents are written. Can be #IG_CURRENT_VCPU for this CPU
/// @param[in]  XsaveArea   Pointer to a #XSAVE_AREA structure containing the buffer with the data to be written
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_SET_XSAVE_AREA, (void *)(SIZE_T)CpuNumber,
                             (PBYTE)XsaveArea->XsaveArea, XsaveArea->Size);
}


INTSTATUS
IntFindKernelPcr(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Pcr
    )
///
/// @brief      Finds the address of the Windows kernel _KPCR
///
/// For 64-bit guests, this is done by reading either the IA32_GS_BASE MSR, or the IA32_KERNEL_GS_BASE MSR if the first
/// one does not point inside the kernel. For 32-bit guests it is obtained from the guest GDT.
///
/// @param[in]  CpuNumber   The CPU for which the _KPCR address is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Pcr         On success, the address of the _KPCR structure
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if the _KPCR address is not found
///
{
    INTSTATUS status;
    QWORD efer;

    // Read the EFER.
    status = IntEferRead(CpuNumber, &efer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntEferRead failed: 0x%08x\n", status);
        return status;
    }

    // Get the kernel KPCR.
    if (efer & EFER_LMA)
    {
        QWORD gsbase;

        // 64 bit-mode, KPCR is in IA32_GS_BASE or IA32_KERNEL_GS_BASE.
        status = IntGsRead(CpuNumber, &gsbase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGsRead failed: 0x%08x\n", status);
            return status;
        }

        // If the current IA32_GS_BASE doesn't point inside the kernel, read IA32_KERNEL_GS_BASE.
        if (0 == (gsbase & 0x8000000000000000))
        {
            WARNING("[WARNING][CPU %d] IA32_GS_BASE MSR does not point inside kernel (%llx)\n",
                    gVcpu->Index, gsbase);

            status = IntKernelGsRead(CpuNumber, &gsbase);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernelGsRead failed: 0x%08x\n", status);
                return status;
            }

            // If we still don't have the kernel GS, bail out.
            if (0 == (gsbase & 0x8000000000000000))
            {
                ERROR("[ERROR][CPU %d] IA32_KERNEL_GS_BASE MSR does not point inside kernel (%llx)\n",
                      gVcpu->Index, gsbase);
                return INT_STATUS_NOT_FOUND;
            }
        }

        *Pcr = gsbase;
    }
    else
    {
        QWORD gdtbase;
        WORD gdtlimit;
        SEGMENT_DESCRIPTOR32 fsdesc;

        // Get the GDT base.
        status = IntGdtFindBase(CpuNumber, &gdtbase, &gdtlimit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGdtFindBase failed: 0x%08x\n", status);
            return status;
        }

        // Make sure descriptor 0x30 is alright.
        if (0x30 + 8 > gdtlimit)
        {
            ERROR("[ERROR] Kernel FS points outside the GDT 0x%016llx:%x\n", gdtbase, gdtlimit);
            return INT_STATUS_BUFFER_OVERFLOW;
        }

        // Read the descriptor.
        status = IntKernVirtMemRead(gdtbase + 0x30, sizeof(fsdesc), &fsdesc, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        *Pcr = fsdesc.Base1 | (fsdesc.Base << 24);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGetAllRegisters(
    _In_ DWORD CpuNumber,
    _Out_ PIG_ARCH_REGS Regs
    )
///
/// @brief      Returns the entire guest register state. This will return the GPRs, control registers, and IDT and
///             GDT base and limit. This also bypasses the cache used by #IntGetGprs
///
/// @param[in]  CpuNumber   The CPU for which the _KPCR address is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] Regs        On success, will contain the values of the registers
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_REGISTER_STATE, (void *)(size_t)CpuNumber, (PBYTE)Regs,
                             sizeof(IG_ARCH_REGS));
}


INTSTATUS
IntGetCurrentEptIndex(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *EptpIndex
    )
///
/// @brief      Get the EPTP index of the currently loaded EPT
///
/// @param[in]  CpuNumber   The CPU for which the _KPCR address is read. Can be #IG_CURRENT_VCPU for this CPU
/// @param[out] EptpIndex   On success, will contain the EPT index
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (NULL == EptpIndex)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_EPTP_INDEX, (void *)(size_t)CpuNumber,
                               (void *)EptpIndex, sizeof(DWORD));

    // In case the IG_QUERY_INFO_CLASS_EPTP_INDEX is not supported, we will assume the current EPT is always 0.
    if (INT_STATUS_OPERATION_NOT_SUPPORTED == status)
    {
        *EptpIndex = 0;
        status = INT_STATUS_SUCCESS;
    }

    return status;
}


INTSTATUS
IntGetMaxGpfn(
    _Out_ QWORD *MaxGpfn
    )
///
/// @brief      Get the last physical page frame number accessible by the guest
///
/// In practice, it has been observed that this is not entirely accurate. See #IntGuestGetLastGpa
///
/// @param[out] MaxGpfn     The last physical page frame number available to the guest
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntQueryGuestInfo(IG_QUERY_INFO_CLASS_MAX_GPFN, NULL, (void *)MaxGpfn, sizeof(*MaxGpfn));
}
