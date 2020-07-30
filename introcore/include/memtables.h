/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _MEM_TABLES_H_
#define _MEM_TABLES_H_

#include "thread_safeness.h"


#define MAX_MEM_TABLE_SIZE              256
// PUSHF (opcode = 1)
// PUSH dst (rex + opcode = 1 + 1 = 2)
// PUSH idx (rex + opcode = 1 + 1 = 2)
// MOV [rsp + 8], slack_addr low (opcode + modrm + sub + disp + imm = 1 + 1 + 1 + 1 + 4 = 8)
// MOV [rsp + C], slack_addr high (opcode + modrm + sub + disp + imm = 1 + 1 + 1 + 1 + 4 = 8)
// IMUL idx, idx, 11 (rex + opcode + modrm + imm = 1 + 1 + 1 + 1 = 4)
// ADD [rsp + 8], idx (rex + opcode + modrm + sib + disp = 1 + 1 + 1 + 1 + 1 = 5)
// POP idx (rex + opcode = 1 + 1 = 2)
// POP dst (rex + opcode = 1 + 1 = 2)
// MOV [rsp - 8], 0 (rex + opcode + modrm + sib + disp + imm4 = 9 bytes)
// POPF (opcode = 1)
// JMP dst (rex + opcode + modrm = 1 + 1 + 1 = 3)
// 11 * number of entries
#define MEM_TABLE_HEADER_SIZE           47
#define MEM_TABLE_ENTRY_SIZE            11u
#define MAX_MEM_TABLE_SLACK_SIZE        ((MEM_TABLE_HEADER_SIZE) + (MEM_TABLE_ENTRY_SIZE) * (MAX_MEM_TABLE_SIZE))


///
/// Describes a relocated mem-table instruction.
///
typedef struct _MEM_TABLE_RELOC
{
    LIST_ENTRY  Link;           ///< List element link.

    QWORD       Rip;            ///< RIP of the instrumented instruction.
    QWORD       TableGva;       ///< Guest virtual address of the switch-case table accessed by the instruction.
    QWORD       Hits;           ///< Number of times this instruction generated a read EPT violation.

    QWORD       SlackAddress;   ///< Slack address where the handler was allocated.
    DWORD       SlackSize;      ///< Size of the allocated slack buffer.
    void        *InsCloak;      ///< Instrumented instruction cloak handle.
    void        *SlackCloak;    ///< Slack handler cloak handle.

    BOOLEAN     Patched;        ///< True if the instruction has been instrumented.
    BOOLEAN     Ignored;        ///< True if we didn't manage to hook it.
    BOOLEAN     InAgent;        ///< True if we relocated the instruction inside the PT filter agent.
    BOOLEAN     Dumped;         ///< TRUE if it's a problematic table and we dumped it's content in an error
} MEM_TABLE_RELOC, *PMEM_TABLE_RELOC;


//
// API
//
BOOLEAN
IntMtblIsPtrInReloc(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ QWORD *Table
    );

INTSTATUS
IntMtblCheckAccess(
    void
    );

void
IntMtblDisable(
    void
    );

INTSTATUS
IntMtblRemoveAgentEntries(
    void
    );

BOOLEAN
IntMtblInsRelocated(
    _In_ QWORD Rip
    );

INTSTATUS
IntMtblUninit(
    void
    );

#endif // _MEM_TABLES_H_
