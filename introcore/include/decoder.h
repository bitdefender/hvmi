/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DECODER_H_
#define _DECODER_H_

#include "glue.h"
#include "bddisasm.h"

///
/// This is an enum describing supported page-table modification instructions.
///
enum
{
    opMov = 0,  ///< MOV instruction.
    opXor,      ///< XOR instruction.
    opAnd,      ///< AND instruction.
    opOr,       ///< OR instruction.
    opBts,      ///< BTS instruction.
    opAdd       ///< ADD instruction.
};

#define DEC_EFLAG_CF            0x00000001

/// Gets the value of the indicated flag.
#define DEC_GET_FLAG(eflags, flag)   ((eflags) >> (((flag) - 1) % 64))

/// Flag used to hint the instruction decoder to not use the instruction cache.
#define DEC_OPT_NO_CACHE        0x00000001

/// Invalid GPA placeholder.
#define DEC_INVALID_GPA         0xFFFFFFFFFFFFFFFF

/// High 32 bits mask.
#define QWORD_HIGH_PART_MASK    0xFFFFFFFF00000000

/// Describes a memory address, as used in an instruction.
typedef struct _MEMADDR
{
    QWORD       Gla;        ///< The guest linear address.
    DWORD       Size;       ///< The size.
    BYTE        Access;     ///< Access (read, write, or a combination).
    BYTE        Reserved1;
    WORD        Reserved2;
} MEMADDR, *PMEMADDR;


/// Describes an operand value.
typedef struct _OPERAND_VALUE
{
    union
    {
        BYTE    ByteValues[ND_MAX_REGISTER_SIZE];
        WORD    WordValues[ND_MAX_REGISTER_SIZE / 2];
        DWORD   DwordValues[ND_MAX_REGISTER_SIZE / 4];
        QWORD   QwordValues[ND_MAX_REGISTER_SIZE / 8];
    } Value;                ///< The actual operand value.

    DWORD       Size;       ///< The operand size.
} OPERAND_VALUE, *POPERAND_VALUE;


//
// API
//
INTSTATUS
IntDecDecodeInstruction(
    _In_ IG_CS_TYPE CsType,
    _In_ QWORD Gva,
    _Out_ void *Instrux
    );

INTSTATUS
IntDecDecodeInstructionFromBuffer(
    _In_reads_bytes_(BufferSize) PBYTE Buffer,
    _In_ size_t BufferSize,
    _In_ IG_CS_TYPE CsType,
    _Out_ void *Instrux
    );

INTSTATUS
IntDecDecodeInstructionAtRip(
    _In_ DWORD CpuNumber,
    _In_ IG_ARCH_REGS *Registers,
    _In_opt_ IG_SEG_REGS *Segments,
    _Out_ INSTRUX *Instrux
    );

INTSTATUS
IntDecDecodeInstructionAtRipWithCache(
    _In_ void *Cache,
    _In_ DWORD CpuNumber,
    _In_ PIG_ARCH_REGS Registers,
    _Out_ PINSTRUX Instrux,
    _In_ DWORD Options,
    _Out_opt_ BOOLEAN *CacheHit,
    _Out_opt_ BOOLEAN *Added
    );

INTSTATUS
IntDecDecodeAccessSize(
    _In_ PINSTRUX Instrux,
    _In_ PIG_ARCH_REGS Registers,
    _In_ QWORD Gla,
    _In_ BYTE AccessType,
    _Out_ DWORD *AccessSize
    );

INTSTATUS
IntDecGetWrittenValueFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PBYTE MemoryValue,
    _Out_ OPERAND_VALUE *WrittenValue
    );

INTSTATUS
IntDecEmulateInstruction(
    _In_ DWORD CpuNumber,
    _In_ PINSTRUX Instrux
    );

INTSTATUS
IntDecEmulatePTWrite(
    _Out_ QWORD *NewValue
    );

#define PW_FLAGS_SET_A  BIT(0)  /// Set the Access bit.
#define PW_FLAGS_SET_D  BIT(1)  /// Set the Dirty bit.

INTSTATUS
IntDecEmulatePageWalk(
    _In_ QWORD Gla,
    _In_ QWORD Cr3,
    _In_ DWORD Flags
    );

INTSTATUS
IntDecGetAccessedMemCount(
    _In_ PINSTRUX Instrux,
    _Out_ DWORD *Count
    );

INTSTATUS
IntDecGetAccessedMem(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _Out_writes_(*Count) MEMADDR *Gla,
    _Inout_ DWORD *Count
    );

INTSTATUS
IntDecGetSseRegValue(
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _In_ DWORD Reg,
    _In_ DWORD Size,
    _Out_ OPERAND_VALUE *Value
    );

INTSTATUS
IntDecSetSseRegValue(
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _In_ DWORD Reg,
    _In_ DWORD Size,
    _In_ OPERAND_VALUE *Value,
    _In_ BOOLEAN Commit
    );

INTSTATUS
IntDecEmulateRead(
    _In_ PINSTRUX Instrux,
    _In_opt_ BYTE *SrcValueBuffer
    );

INTSTATUS
IntDecComputeLinearAddress(
    _In_ PINSTRUX Instrux,
    _In_ PND_OPERAND Operand,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    );

INTSTATUS
IntDecDecodeDestinationLinearAddressFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    );

INTSTATUS
IntDecDecodeSourceLinearAddressFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    );

INTSTATUS
IntDecGetMaxvl(
    _Out_ ND_OPERAND_SIZE *Maxvl
    );

#endif // _DECODER_H_
