/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRO_CPU_H_
#define _INTRO_CPU_H_

#include "introtypes.h"
#include "processor.h"

///
/// @brief  An 64-bit interrupt gate as defined by the Intel docs.
///
typedef union _INTERRUPT_GATE
{
    QWORD       Raw[2];
    struct
    {
        WORD    Offset_15_0;
        WORD    Selector;
        WORD    Fields;
        WORD    Offset_31_16;
        DWORD   Offset_63_32;
        DWORD   Reserved2;
    };
} INTERRUPT_GATE, *PINTERRUPT_GATE;

///
/// @brief  An 32-bit interrupt gate as defined by the Intel docs.
///
typedef union _INTERRUPT_GATE32
{
    QWORD           Raw;
    struct
    {
        WORD        Offset_15_0;
        WORD        Selector;
        WORD        Fields;
        WORD        Offset_31_16;
    };
} INTERRUPT_GATE32, *PINTERRUPT_GATE32;

///
/// @brief   Segment descriptor for 32-bit systems.
///
typedef struct _SEGMENT_DESCRIPTOR32
{
    QWORD               Limit1 : 16;
    QWORD               Base1 : 24;
    QWORD               Attr1 : 8;
    QWORD               Limit2 : 4;
    QWORD               Attr2 : 4;
    QWORD               Base : 8;
} SEGMENT_DESCRIPTOR32, *PSEGMENT_DESCRIPTOR32;

///
/// @brief   XSAVE area container.
///
typedef struct _XSAVE_AREA
{
    DWORD               Size;       ///< The size of the XSAVE area. XsaveArea has at least Size bytes.
    IG_XSAVE_AREA       *XsaveArea; ///< The contents of the XSAVE area.
} XSAVE_AREA;

#pragma pack(push)
#pragma pack(1)

///
/// @brief  A descriptor table register. Valid for IDTR and GDTR.
///
typedef struct _DTR
{
    WORD    Limit;
    QWORD   Base;
} DTR, *PDTR;

#pragma pack(pop)

//
// IA32_LBR_SELECT & IA32_LBR_TOS aren't actually architectural, they are specific
// to micro architectures >= Nehalem/Westmere
//
#define MSR_LBR_0_FROM_IP           0x00000680
#define MSR_LBR_1_FROM_IP           0x00000681
#define MSR_LBR_2_FROM_IP           0x00000682
#define MSR_LBR_3_FROM_IP           0x00000683
#define MSR_LBR_4_FROM_IP           0x00000684
#define MSR_LBR_5_FROM_IP           0x00000685
#define MSR_LBR_6_FROM_IP           0x00000686
#define MSR_LBR_7_FROM_IP           0x00000687
#define MSR_LBR_8_FROM_IP           0x00000688
#define MSR_LBR_9_FROM_IP           0x00000689
#define MSR_LBR_A_FROM_IP           0x0000068A
#define MSR_LBR_B_FROM_IP           0x0000068B
#define MSR_LBR_C_FROM_IP           0x0000068C
#define MSR_LBR_D_FROM_IP           0x0000068D
#define MSR_LBR_E_FROM_IP           0x0000068E
#define MSR_LBR_F_FROM_IP           0x0000068F

#define MSR_LBR_0_TO_IP             0x000006C0
#define MSR_LBR_1_TO_IP             0x000006C1
#define MSR_LBR_2_TO_IP             0x000006C2
#define MSR_LBR_3_TO_IP             0x000006C3
#define MSR_LBR_4_TO_IP             0x000006C4
#define MSR_LBR_5_TO_IP             0x000006C5
#define MSR_LBR_6_TO_IP             0x000006C6
#define MSR_LBR_7_TO_IP             0x000006C7
#define MSR_LBR_8_TO_IP             0x000006C8
#define MSR_LBR_9_TO_IP             0x000006C9
#define MSR_LBR_A_TO_IP             0x000006CA
#define MSR_LBR_B_TO_IP             0x000006CB
#define MSR_LBR_C_TO_IP             0x000006CC
#define MSR_LBR_D_TO_IP             0x000006CD
#define MSR_LBR_E_TO_IP             0x000006CE
#define MSR_LBR_F_TO_IP             0x000006CF

#define MSR_LER_FROM_IP             0x000001DD
#define MSR_LER_TO_IP               0x000001DE

#define LBR_STACK_SIZE              16


//
// Cpu registers/structures access
//
INTSTATUS
IntEferRead(
    _In_ QWORD CpuNumber,
    _Out_ QWORD *Efer
    );

INTSTATUS
IntRipRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Rip
    );

INTSTATUS
IntIdtFindBase(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Base,
    _Out_opt_ WORD *Limit
    );

INTSTATUS
IntIdtGetEntry(
    _In_ DWORD CpuNumber,
    _In_ DWORD Entry,
    _Out_ QWORD *Handler
    );

INTSTATUS
IntGdtFindBase(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *GdtBase,
    _Out_opt_ WORD *GdtLimit
    );

INTSTATUS
IntFsRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *FsValue
    );

INTSTATUS
IntGsRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *GsValue
    );

INTSTATUS
IntCr0Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr0Value
    );

INTSTATUS
IntCr3Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr3Value);

INTSTATUS
IntCr4Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr4Value
    );

INTSTATUS
IntCr8Read(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Cr8Value
    );

INTSTATUS
IntSysenterRead(
    _In_ DWORD CpuNumber,
    _Out_opt_ QWORD *SysCs,
    _Out_opt_ QWORD *SysEip,
    _Out_opt_ QWORD *SysEsp
    );

INTSTATUS
IntSyscallRead(
    _In_ DWORD CpuNumber,
    _Out_opt_ QWORD *SysStar,
    _Out_opt_ QWORD *SysLstar
    );

INTSTATUS
IntDebugCtlRead(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *DebugCtl
    );

INTSTATUS
IntLbrRead(
    _In_ DWORD BuffersSize,
    _Out_writes_(BuffersSize) QWORD *LbrFrom,
    _Out_writes_(BuffersSize) QWORD *LbrTo
    );

INTSTATUS
IntLerRead(
    _Out_ QWORD *LerFrom,
    _Out_ QWORD *LerTo
    );

DWORD
IntGetCurrentCpu(
    void
    );

INTSTATUS
IntGetGprs(
    _In_ DWORD CpuNumber,
    _Out_ PIG_ARCH_REGS Regs
    );

INTSTATUS
IntSetGprs(
    _In_ DWORD CpuNumber,
    _In_ PIG_ARCH_REGS Regs
    );

INTSTATUS
IntGetCurrentRing(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *Ring
    );

INTSTATUS
IntGetCurrentMode(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *Mode
    );

INTSTATUS
IntGetSegs(
    _In_ DWORD CpuNumber,
    _Out_ PIG_SEG_REGS Regs
    );

INTSTATUS
IntGetXsaveAreaSize(
    _Out_ DWORD *Size
    );

INTSTATUS
IntGetXsaveArea(
    _In_ DWORD CpuNumber,
    _Out_ XSAVE_AREA *XsaveArea
    );

INTSTATUS
IntSetXsaveArea(
    _In_ DWORD CpuNumber,
    _In_ XSAVE_AREA *XsaveArea
    );

///
/// @brief  Frees an XSAVE area.
///
/// @param[in]  xa      A #XSAVE_AREA structure to be cleaned up. Note that the structure itself is not freed, only
///                     its internal buffers.
///
#define IntFreeXsaveArea(xa)    HpFreeAndNullWithTag(&(xa).XsaveArea, IC_TAG_XSAVE)

INTSTATUS
IntGetXcr0(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Xcr0Value
    );

INTSTATUS
IntFindKernelPcr(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Pcr
    );

INTSTATUS
IntGetCurrentEptIndex(
    _In_ DWORD CpuNumber,
    _Out_ DWORD *EptpIndex
    );

INTSTATUS
IntGetAllRegisters(
    _In_ DWORD CpuNumber,
    _Out_ PIG_ARCH_REGS Regs
    );

INTSTATUS
IntGetMaxGpfn(
    _Out_ QWORD *MaxGpfn
    );

#endif // _INTRO_CPU_H_
