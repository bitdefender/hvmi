/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PROCESSOR_H_
#define _PROCESSOR_H_

#include "introdefs.h"


#define CPU_EFLAGS_CF           BIT(0)
#define CPU_EFLAGS_FIXED        BIT(1)
#define CPU_EFLAGS_PF           BIT(2)
#define CPU_EFLAGS_AF           BIT(4)
#define CPU_EFLAGS_ZF           BIT(6)
#define CPU_EFLAGS_SF           BIT(7)
#define CPU_EFLAGS_TF           BIT(8)
#define CPU_EFLAGS_IF           BIT(9)
#define CPU_EFLAGS_DF           BIT(10)
#define CPU_EFLAGS_OF           BIT(11)
#define CPU_EFLAGS_NT           BIT(14)
#define CPU_EFLAGS_RF           BIT(16)
#define CPU_EFLAGS_VM           BIT(17)
#define CPU_EFLAGS_AC           BIT(18)
#define CPU_EFLAGS_VIF          BIT(19)
#define CPU_EFLAGS_VIP          BIT(20)
#define CPU_EFLAGS_ID           BIT(21)


#define CR0_PE                  BIT(0)
#define CR0_MP                  BIT(1)
#define CR0_EM                  BIT(2)
#define CR0_TS                  BIT(3)
#define CR0_ET                  BIT(4)
#define CR0_NE                  BIT(5)
#define CR0_WP                  BIT(16)
#define CR0_AM                  BIT(18)
#define CR0_NW                  BIT(29)
#define CR0_CD                  BIT(30)
#define CR0_PG                  BIT(31)


#define CR4_VME                 BIT(0)
#define CR4_PVI                 BIT(1)
#define CR4_TSD                 BIT(2)
#define CR4_DE                  BIT(3)
#define CR4_PSE                 BIT(4)
#define CR4_PAE                 BIT(5)
#define CR4_MCE                 BIT(6)
#define CR4_PGE                 BIT(7)
#define CR4_PCE                 BIT(8)
#define CR4_OSFXSR              BIT(9)
#define CR4_OSXMMEXCPT          BIT(10)
#define CR4_UMIP                BIT(11)
#define CR4_LA57                BIT(12)
#define CR4_VMXE                BIT(13)
#define CR4_SMXE                BIT(14)
#define CR4_FSGSBASE            BIT(16)
#define CR4_PCIDE               BIT(17)
#define CR4_OSXSAVE             BIT(18)
#define CR4_SMEP                BIT(20)
#define CR4_SMAP                BIT(21)
#define CR4_PKE                 BIT(22)


#define XCR0_X87                BIT(0)
#define XCR0_SSE                BIT(1)
#define XCR0_YMM_HI128          BIT(2)
#define XCR0_BNDREGS            BIT(3)
#define XCR0_BNDCSR             BIT(4)
#define XCR0_OPMASK             BIT(5)
#define XCR0_ZMM_HI256          BIT(6)
#define XCR0_HI16_ZMM           BIT(7)
#define XCR0_PT                 BIT(8)
#define XCR0_PKRU               BIT(9)
// From the Intel SDM:
// software can enable the XSAVE feature set for AVX-512 state only if it
// does so for all three state components, and only if it also does so for AVX state and SSE state.This implies that
// the value of XCR0[7:5] is always either 000b or 111b.
#define XCR0_AVX_512_STATE      (XCR0_ZMM_HI256 | XCR0_HI16_ZMM | XCR0_OPMASK)


#define PFEC_P                  BIT(0)
#define PFEC_RW                 BIT(1)
#define PFEC_US                 BIT(2)
#define PFEC_RSVD               BIT(3)
#define PFEC_ID                 BIT(4)
#define PFEC_PK                 BIT(5)
#define PFEC_SGX                BIT(15)


#define EFER_SCE                BIT(0)
#define EFER_LME                BIT(8)
#define EFER_LMA                BIT(10)
#define EFER_NX                 BIT(11)
#define EFER_SVME               BIT(12)
#define EFER_LMSLE              BIT(13)
#define EFER_FFXSR              BIT(14)


#define DESCRIPTOR_SIZE_32      8
#define DESCRIPTOR_SIZE_64      16

#define VECTOR_DE               0
#define VECTOR_DB               1
#define VECTOR_BP               3
#define VECTOR_OF               4
#define VECTOR_BR               5
#define VECTOR_UD               6
#define VECTOR_NM               7
#define VECTOR_DF               8
#define VECTOR_TS               10
#define VECTOR_NP               11
#define VECTOR_SS               12
#define VECTOR_GP               13
#define VECTOR_PF               14
#define VECTOR_MF               16
#define VECTOR_AC               17
#define VECTOR_MC               18
#define VECTOR_XM               19
#define VECTOR_VE               20

#define NO_ERRORCODE            ((DWORD)-1)


//
// Processor structures definitions
//
#pragma pack(push)
#pragma pack(1)

typedef struct _IDT_ENTRY64
{
    WORD        Offset15_0;
    WORD        Selector;
    WORD        Fields;
    WORD        Offset31_16;
    DWORD       Offset63_32;
    DWORD       Reserved2;
} IDT_ENTRY64, *PIDT_ENTRY64;

typedef struct _IDT_ENTRY32
{
    WORD Offset15_0;
    WORD Selector;
    BYTE Zero;
    BYTE Fields;
    WORD Offset31_16;
} IDT_ENTRY32, *PIDT_ENTRY32;

#pragma pack(pop)

#endif // _PROCESSOR_H_
