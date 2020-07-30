/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VECOMMON_H_
#define _VECOMMON_H_

///
/// @file vecommon.h
///
/// @brief This file is common between the VE driver and the introspection engine.
///
/// This file contains shared definitions, between the VE agent and the Introspection engine. The most important
/// ones are the VE info page (which is kept mapped inside Introcore, for quick access to the instruction and
/// page-table values) and the statuses.
///


/// Major VMCALL number (as defined by Xen, passed in EAX).
#define VE_VMCALL_OP                0x22
/// Minor VMCALL number (as defined by Xen, passed in EDI on x64, EBX on x86).
#define VE_VMCALL_SUBOP             0x18


/// NOP
/// Input: RAX = VE_VMCALL_OP
/// Input: RDI = VE_VMCALL_SUBOP
/// Input: RSI = 0
/// Input: RDX = VE_HCALL_NOP
/// Input: RBX = Ignored
#define VE_HCALL_NOP                0

/// Logs the message string stored by the \#VE driver for the current cpu.
/// Input: RAX = VE_VMCALL_OP
/// Input: RDI = VE_VMCALL_SUBOP
/// Input: RSI = 0
/// Input: RDX = VE_HCALL_BREAK
/// Input: RBX = reason
/// INPUT: RCX = reason parameter
#define VE_HCALL_BREAK              1

/// Trace \#VE agent execution to Introcore.
/// Input: RAX = VE_VMCALL_OP
/// Input: RDI = VE_VMCALL_SUBOP
/// Input: RSI = 0
/// Input: RDX = VE_HCALL_TRACE
/// Input: RBX = parameter 1
/// INPUT: RCX = parameter 2
#define VE_HCALL_TRACE              2

/// Raises an EPT exception.
/// Input: RAX = VE_VMCALL_OP
/// Input: RDI = VE_VMCALL_SUBOP
/// Input: RSI = 0
/// Input: RDX = VE_HCALL_RAISE_EPT
#define VE_HCALL_RAISE_EPT          3



#pragma pack(push)
#pragma pack(1)


///
/// General purpose registers state. Offsets are relative to the beginning of the VE info page.
///
typedef struct _REGISTERS
{
    QWORD       RAX;            // Offset 0x30
    QWORD       RCX;            // Offset 0x38
    QWORD       RDX;            // Offset 0x40
    QWORD       RBX;            // Offset 0x48
    QWORD       RSP;            // Offset 0x50
    QWORD       RBP;            // Offset 0x58
    QWORD       RSI;            // Offset 0x60
    QWORD       RDI;            // Offset 0x68
    QWORD       R8;             // Offset 0x70
    QWORD       R9;             // Offset 0x78
    QWORD       R10;            // Offset 0x80
    QWORD       R11;            // Offset 0x88
    QWORD       R12;            // Offset 0x90
    QWORD       R13;            // Offset 0x98
    QWORD       R14;            // Offset 0xA0
    QWORD       R15;            // Offset 0xA8
    QWORD       RIP;            // Offset 0xB0
    QWORD       CS;             // Offset 0xB8
    QWORD       RFLAGS;         // Offset 0xC0
    QWORD       CR0;            // Offset 0xC8
    QWORD       CR3;            // Offset 0xD0
    QWORD       CR4;            // Offset 0xD8
    QWORD       DR7;            // Offset 0xE0
    QWORD       SS;             // Offset 0xE8
    QWORD       MXCSR;          // Offset 0xF0
    QWORD       Reserved2;      // Offset 0xF8
    BYTE        XMM[256];       // Offset 0x100-0x200

} REGISTERS, *PREGISTERS;


///
/// The VE information page. One such structure, that spans an entire page, must be present for each VCPU.
/// The address of the VE info page (host physical address) is stored inside the VMCS, and when a VE is
/// generated, the CPU will store in it information related to the event. Right now, only EPT violation
/// events can be delivered as virtualization exceptions. The beginning of the page is reserved for the
/// CPU, but the rest of it is used by the VE agent and Introcore.
///
typedef struct _VECPU
{
    // #VE information area.
    DWORD           Reason;                 ///< Same as the basic VM Exit reason.
    DWORD           Reserved;               ///< Reserved. This field will be set to 0xFFFFFFFF when a VE is delivered.
                                            ///< If this field is 0xFFFFFFFF, the CPU will not generate VEs anymore;
                                            ///< instead, EPT violations will be delivered as usual.
    QWORD           Qualification;          ///< Same as the exit qualification provided on VM Exits.
    QWORD           GuestLinearAddress;     ///< Same as the GLA field provided on EPT Violations.
    QWORD           GuestPhysicalAddress;   ///< Same as the GPA field provided on EPT Violations.
    QWORD           EptpIndex;              ///< The index of the EPT in which the fault took place.
    QWORD           Reserved2;              ///< Reserved by Intel.

    REGISTERS       Registers;              ///< Offset 0x30 - 0x200, general purpose registers.

    PBYTE           ProtectedStack;         ///< Offset 0x200, the protected stack.
    PBYTE           OriginalStack;          ///< Offset 0x208, the original stack.

    QWORD           OldValue;               ///< Old page-table entry.
    QWORD           NewValue;               ///< New page-table entry.

    QWORD           VeTotal;                ///< Total number of VEs.
    QWORD           VeMm;                   ///< Number of VEs generated by the OS.
    QWORD           VePageWalk;             ///< Number of VEs generated by the CPU page-walker.
    QWORD           VeIgnoredTotal;         ///< Total number of VEs that were handled inside the guest, without
                                            ///< reporting them to Introcore (no VM exit).
    QWORD           VeIgnoredCache;         ///< Total number of VEs that were ignored because the a cache hit
                                            ///< (page-table entries which are not monitored by Introcore).
    QWORD           VeIgnoredIrrelevant;    ///< Total number of VEs ignored because the modification was not
                                            ///< relevant (for example, the A bit was cleared).
    
    QWORD           TscTotal;               ///< Total number of CPU ticks spent inside the agent.
    QWORD           TscCount;               ///< Total number of times the agent has been invoked.

    // fetched instruction bytes.
    BYTE            Instruction[16];        ///< Current instruction bytes.

    QWORD           Self;                   ///< Pointer to self.
    QWORD           Index;                  ///< VCPU index.

    BOOLEAN         Raised;                 ///< True if the current VE has been sent to Introcore via VMCALL.

} VECPU, *PVECPU;

#pragma pack(pop)

/// Total size of the stack used by the VE agent.
#define VE_STACK_SIZE       0x4000

/// Currently, VE supports only 64 VCPUs max.
#define VE_MAX_CPUS         64


///
/// VE info page. Used in order to force the size of the page to exactly 4K.
///
typedef union _VECPU_PAGE
{
    VECPU           Cpu;                    ///< The VE info page.
    BYTE            Page[0x1000];           ///< Padding.
} VECPU_PAGE, *PVECPU_PAGE;


///
/// VE agent stack.
///
typedef struct _VE_STACK
{
    BYTE        Stack[VE_STACK_SIZE];       ///< The stack contents.
} VE_STACK, *PVE_STACK;


///
/// Page-Table cache related structures. The cache uses a double indexing algorithm; assuming value X is
/// a page-table entry address:
/// - Use bits [12, 17] in X to index the cache line
/// - Use bits [3, 8] in X to index a bucket/way inside the line
/// - Iterate each entry inside the bucket, and compare it with X.
/// One page will contain 512 entries, 64 lines, 8 buckets, so this behaves like a 4K 8-ways associative cache.
///

/// 64 cache lines (pages), indexed by bits [12, 17] inside the page-table address.
#define VE_CACHE_LINES      64
/// 64 buckets/line, indexed by bits [3, 8] inside the page-table entry address.
#define VE_CACHE_BUCKETS    64
/// 8 entries/bucket.
#define VE_CACHE_ENTRIES    8

#define VE_CACHE_GET_LINE(x)        (((x) >> 12) & (VE_CACHE_LINES - 1))
#define VE_CACHE_GET_BUCKET(x)      (((x) >> 3) & (VE_CACHE_BUCKETS - 1))

///
/// One VE cache line.
///
typedef struct _VE_CACHE_LINE
{
    QWORD       Entries[VE_CACHE_BUCKETS][VE_CACHE_ENTRIES]; ///< VE cache entries.
} VE_CACHE_LINE;


///
/// VE status.
///
typedef unsigned int VESTATUS;

#define VE_STATUS_SUCCESS               0x00000000
#define VE_STATUS_ERROR                 0x80000000
#define VE_STATUS_NOT_SUPPORTED         0x80000001
#define VE_STATUS_DISASM_ERROR          0x80000002
#define VE_STATUS_PAGE_NOT_PRESENT      0x80000003
#define VE_STATUS_ACCESS_DENIED         0x80000004

#define VE_SUCCESS(s)                   ((s) < VE_STATUS_ERROR)

#define VE_BREAK_UNKNOWN_EXIT           0x00000001
#define VE_BREAK_PAGE_WALK_FAILED       0x00000002
#define VE_BREAK_EMULATION_FAILED       0x00000003
#define VE_BREAK_CS_NOT_KERNEL          0x00000004


#endif // _VECOMMON_H_
