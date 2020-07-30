/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CPU_H_
#define _CPU_H_

#define BIT(x)                  (1ULL << (x))

// RFLAGS definitions
#define RFLAGS_CF               BIT(0)
#define RFLAGS_PF               BIT(2)
#define RFLAGS_AF               BIT(4)
#define RFLAGS_ZF               BIT(6)
#define RFLAGS_SF               BIT(7)
#define RFLAGS_TF               BIT(8)
#define RFLAGS_IF               BIT(9)
#define RFLAGS_DF               BIT(10)
#define RFLAGS_OF               BIT(11)
#define RFLAGS_IOPL             (BIT(12)|BIT(13))
#define RFLAGS_NT               BIT(14)
#define RFLAGS_RF               BIT(16)
#define RFLAGS_VM               BIT(17)
#define RFLAGS_AC               BIT(18)
#define RFLAGS_VIF              BIT(19)
#define RFLAGS_VIP              BIT(20)
#define RFLAGS_ID               BIT(21)


// CR0 bits
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


// CR4 bits
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
#define CR4_VMXE                BIT(13)
#define CR4_SMXE                BIT(14)
#define CR4_PCIDE               BIT(17)
#define CR4_OSXSAVE             BIT(18)
#define CR4_SMEP                BIT(20)
#define CR4_SMAP                BIT(21)
#define CR4_PKE                 BIT(22)


// IA32_EFER bits
#define EFER_SCE                BIT(0)
#define EFER_LME                BIT(8)
#define EFER_LMA                BIT(10)
#define EFER_NXE                BIT(11)
#define EFER_SVME               BIT(12)
#define EFER_LMSLE              BIT(13)
#define EFER_FFXSR              BIT(14)
#define EFER_TCE                BIT(15)


// DR6 bits
#define DR6_B0                  BIT(0)
#define DR6_B1                  BIT(1)
#define DR6_B2                  BIT(2)
#define DR6_B3                  BIT(3)
#define DR6_BD                  BIT(13)
#define DR6_BS                  BIT(14)
#define DR6_BT                  BIT(15)
#define DR6_RTM                 BIT(16)


// MSR definitions
#define MSR_IA32_MTRRCAP            0x000000FE
#define MSR_IA32_MTRR_PHYSBASE0     0x00000200
#define MSR_IA32_MTRR_PHYSMASK0     0x00000201
#define MSR_IA32_MTRR_DEF_TYPE      0x000002FF
#define MSR_IA32_MTRR_FIX64K_00000  0x00000250
#define MSR_IA32_MTRR_FIX16K_80000  0x00000258
#define MSR_IA32_MTRR_FIX16K_A0000  0x00000259
#define MSR_IA32_MTRR_FIX4K_C0000   0x00000268
#define MSR_IA32_MTRR_FIX4K_C8000   0x00000269
#define MSR_IA32_MTRR_FIX4K_D0000   0x0000026A
#define MSR_IA32_MTRR_FIX4K_D8000   0x0000026B
#define MSR_IA32_MTRR_FIX4K_E0000   0x0000026C
#define MSR_IA32_MTRR_FIX4K_E8000   0x0000026D
#define MSR_IA32_MTRR_FIX4K_F0000   0x0000026E
#define MSR_IA32_MTRR_FIX4K_F8000   0x0000026F
#define IA32_APIC_BASE              0x0000001B
#define IA32_X2APIC_APICID          0x00000802
#define IA32_EFER                   0xC0000080
#define IA32_TSC_AUX                0xC0000103


// LAPIC registers
#define LAPIC_ID_REG            0x00000020

// Paging modes.
typedef enum _PAGING_MODE
{
    PagingLongMode,
    PagingPaeMode,
    PagingNormalMode,
    PagingNone,
} PAGING_MODE;


// Page size.
#define PAGE_SIZE               (4096)      // Default page size on x86: 4K
#define PAGE_4K                 (4096)
#define PAGE_2M                 (2 * 1024 * 1024)
#define PAGE_4M                 (4 * 1024 * 1024)
#define PAGE_1G                 (1 * 1024 * 1024 * 1024)

// Page masks.
#define PAGE_MASK               0xFFFFFFFFFFFFF000
#define PAGE_OFFSET             0xFFF
#define PAGE_PHYS_MASK          0x000FFFFFFFFFF000

// VMFUNCs
#define VMFUNC_EPT_SWITCH       0

// Paging bits inside the page tables entries. Some of these are valid only for the PTE, the final entry.
#define PT_P                    0x0000000000000001
#define PT_RW                   0x0000000000000002
#define PT_US                   0x0000000000000004
#define PT_PWT                  0x0000000000000008
#define PT_PCD                  0x0000000000000010
#define PT_A                    0x0000000000000020
#define PT_D                    0x0000000000000040
#define PT_PAT                  0x0000000000000080
#define PT_PS                   0x0000000000000080
#define PT_G                    0x0000000000000100
#define PT_IGNORED              0x0000000000000E00
#define PT_PK                   0x7800000000000000
#define PT_XD                   0x8000000000000000


//
// Page fault error code bits.
//
#define PFEC_P                  0x0001  // The page was present of 1.
#define PFEC_RW                 0x0002  // The access was data write if 1.
#define PFEC_US                 0x0004  // The access was from user mode if 1.
#define PFEC_RSVD               0x0008  // The fault was due to reserved bits set.
#define PFEC_IF                 0x0010  // The access was an instruction fetch.
#define PFEC_PK                 0x0020  // The fault was due to Protection Key.
#define PFEC_SGX                0x8000  // The fault is related to SGX.


//
// IDT exceptions.
//
#define IDT_DE_INDEX            0
#define IDT_DB_INDEX            1
#define IDT_NMI_INDEX           2
#define IDT_BP_INDEX            3
#define IDT_OF_INDEX            4
#define IDT_BR_INDEX            5
#define IDT_UD_INDEX            6
#define IDT_NM_INDEX            7
#define IDT_DF_INDEX            8
#define IDT_NE_INDEX            9
#define IDT_TS_INDEX            10
#define IDT_NP_INDEX            11
#define IDT_SS_INDEX            12
#define IDT_GP_INDEX            13
#define IDT_PF_INDEX            14
#define IDT_MF_INDEX            16
#define IDT_AC_INDEX            17
#define IDT_MC_INDEX            18
#define IDT_XM_INDEX            19
#define IDT_VE_INDEX            20



// Exit reasons - same as the VM exit reasons. Note that #VE will deliver the reason. However, as of now, only
// EXIT_REASON_EPT_VIOLATION is defined as being valid with #VE.
#define EXIT_REASON_EXCEPTION_NMI                       0
#define EXIT_REASON_EXTERNAL_INTERRUPT                  1
#define EXIT_REASON_TRIPLE_FAULT                        2
#define EXIT_REASON_INIT                                3
#define EXIT_REASON_SIPI                                4
#define EXIT_REASON_SMI                                 5
#define EXIT_REASON_OTHER_SMI                           6
#define EXIT_REASON_INTERRUPT_WINDOW                    7
#define EXIT_REASON_NMI_WINDOW                          8
#define EXIT_REASON_TASK_SWITCH                         9
#define EXIT_REASON_CPUID                               10
#define EXIT_REASON_GETSEC                              11
#define EXIT_REASON_HLT                                 12
#define EXIT_REASON_INVD                                13
#define EXIT_REASON_INVLPG                              14
#define EXIT_REASON_RDPMC                               15
#define EXIT_REASON_RDTSC                               16
#define EXIT_REASON_RSM                                 17
#define EXIT_REASON_VMCALL                              18
#define EXIT_REASON_VMCLEAR                             19
#define EXIT_REASON_VMLAUNCH                            20
#define EXIT_REASON_VMPTRLD                             21
#define EXIT_REASON_VMPTRST                             22
#define EXIT_REASON_VMREAD                              23
#define EXIT_REASON_VMRESUME                            24
#define EXIT_REASON_VMWRITE                             25
#define EXIT_REASON_VMOFF                               26
#define EXIT_REASON_VMON                                27
#define EXIT_REASON_CR_ACCESS                           28
#define EXIT_REASON_DR_ACCESS                           29
#define EXIT_REASON_IO_INSTRUCTION                      30
#define EXIT_REASON_MSR_READ                            31
#define EXIT_REASON_MSR_WRITE                           32
#define EXIT_REASON_INVALID_GUEST_STATE                 33
#define EXIT_REASON_MSR_LOADING                         34
#define EXIT_REASON_MWAIT_INSTRUCTION                   36
#define EXIT_REASON_MONITOR_TRAP_FLAG                   37
#define EXIT_REASON_MONITOR                             39
#define EXIT_REASON_PAUSE                               40
#define EXIT_REASON_MACHINE_CHECK                       41
#define EXIT_REASON_TPR_BELOW_THRESHOLD                 43
#define EXIT_REASON_APIC_ACCESS                         44
#define EXIT_REASON_VIRTUALIZED_EOI                     45
#define EXIT_REASON_GDTR_IDTR_ACCESS                    46
#define EXIT_REASON_LDTR_TR_ACCESS                      47
#define EXIT_REASON_EPT_VIOLATION                       48
#define EXIT_REASON_EPT_MISCONFIGURATION                49
#define EXIT_REASON_INVEPT                              50
#define EXIT_REASON_RDTSCP                              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED        52
#define EXIT_REASON_INVVPID                             53
#define EXIT_REASON_WBINVD                              54
#define EXIT_REASON_XSETBV                              55
#define EXIT_REASON_APIC_WRITE                          56
#define EXIT_REASON_RDRAND                              57
#define EXIT_REASON_INVPCID                             58
#define EXIT_REASON_VMFUNC                              59
#define EXIT_REASON_RDSEED                              61
#define EXIT_REASON_XSAVES                              63
#define EXIT_REASON_XRSTORS                             64

#define EPT_QUAL_READ           0x00000001
#define EPT_QUAL_WRITE          0x00000002
#define EPT_QUAL_EXECUTE        0x00000004
#define EPT_QUAL_READABLE       0x00000008
#define EPT_QUAL_WRITABLE       0x00000010
#define EPT_QUAL_EXECUTABLE     0x00000020
#define EPT_QUAL_GLA_VALID      0x00000080
#define EPT_QUAL_GLA_ACCESS     0x00000100
#define EPT_QUAL_NMI_UNBLOCK    0x00001000


// Maximum supported CPUs.
#define MAX_CPU_COUNT       64

#endif // _CPU_H_
