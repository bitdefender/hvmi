/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "memtables.h"
#include "guests.h"
#include "icache.h"
#include "memcloak.h"
#include "ptfilter.h"
#include "slack.h"

static LIST_HEAD gMemTables = LIST_HEAD_INIT(gMemTables); ///< List of memtables.


///
/// @file memtables.c
///
/// @brief Implements instrumentation for switch-case table access instructions.
///
/// Mem-tables is a module used to instrument switch-case tables that are inserted by the compiler inside code pages.
/// Sometimes, these switch-case tables end up being placed inside a page of memory which also contains a hooked
/// API; pages which contain hooked APIs are monitored via EPT against reads, in order to hide the hooks from
/// patch-guard, but if switch-case tables are also present inside those pages, a very high number of read EPT
/// violations will be generated, leading to a very high performance impact.
/// The way we mitigate this is by relocating all such instructions into the slack space of the NT image, and by
/// replacing the memory access instruction with a sequence of instructions that load immediate values instead (the
/// immediate values are the values that would normally be loaded from memory).
///


static INTSTATUS
IntMtblRemoveEntry(
    _In_ PMEM_TABLE_RELOC Reloc
    )
///
/// @brief Removes a mem-table entry.
///
/// This function completely removed a mem-table entry, by removing the hook established on the instrumented
/// instruction, and by removing the handling code injected inside the NT slack space.
///
/// @param[in]  Reloc   Mem-table relocation to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    if (NULL != Reloc->InsCloak)
    {
        IntMemClkUncloakRegion(Reloc->InsCloak, MEMCLOAK_OPT_APPLY_PATCH);

        Reloc->InsCloak = NULL;

        // Flush the cache.
        IntIcFlushAddress(gGuest.InstructionCache, Reloc->Rip, IC_ANY_VAS);
    }

    if (NULL != Reloc->SlackCloak)
    {
        IntMemClkUncloakRegion(Reloc->SlackCloak, MEMCLOAK_OPT_APPLY_PATCH);

        Reloc->SlackCloak = NULL;
    }

    Reloc->Patched = FALSE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntMtblPatchInstruction(
    _Inout_ PMEM_TABLE_RELOC Reloc,
    _In_ PINSTRUX Instrux,
    _In_ PIG_ARCH_REGS Regs
    )
///
/// @brief Relocate and instrument a switch-case load instruction.
///
/// This function will re-write a switch-case load instruction using sequences of instruction which do not access
/// memory (the page which is already read hooked, in particular). The rewriting algorithm relies on loading
/// immediate values into the destination register instead of directly accessing the memory. Each instrumented
/// instruction will contain a header, and a variable size region, with one entry for each value inside the
/// switch-case table.
/// Given a switch-case load instruction, say "MOV       ecx, dword ptr [rdx+rax*4+0x4ea91c]", this is how we
/// rewrite it:
/// 1. We store the header
///     1a. Store a "PUSHFQ" - in order to preserve the flags.
///     1b. Store a "PUSH rcx" - note that we push the destination register from the relocated instruction.
///     1c. Store a "PUSH rax" - note that we push the index register from the memory operand.
///     1d. Store a "MOV [rsp+8], slack_addr_low" and "MOV [rsp+12],slack_addr_high", in order to overwrite the
///         previously saved destination register with the slack address of our immediate table. slack_addr
///         will point to the first immediate block, imm0.
///     1e. Store a "IMUL rax, rax, 11" - we multiply the index register by the size of each immediate block.
///     1f. Store a "ADD [rsp+8], rax" - we add the newly calculated offset to the destination on the stack.
///     1g. Store a "POP rax" - restore the index register.
///     1h. Store a "POP rcx" - this will load the address we wish to jump to in rcx.
///     1i. Store a "MOV [rsp-8], 0" - this removes the pointer that might still point to us (thread-safeness)
///     1j. Store a  "POPFQ" - restore the flags.
///     1k. Store a  "JMP rcx" - jumps to the block of instructions that stores the desired immediate in ecx.
/// 2. We store an array of immediate blocks, which basically load the memory values into the destination
///    register, as immediate values; for each value k inside the switch-case table:
///     2a. Store a  "MOV ecx, immk" - immk is the value located in the switch-case table at index k
///     2b. Store a  "IRETQ" or a "JMP back" - both jump back to the instruction following the instrumented
///         instruction, and resume normal execution, with the desired switch-case table loaded into the
///         proper destination register, but without accessing memory
///
/// For example, let's assume the following:
/// - we instrument instruction "MOV ecx, dword ptr [rdx+rax*4+0x4ea91c]", which lies at 0xFFFF800012340000
/// - the instruction following this instruction is a "JMP [rdx+rcx]", which lies at 0xFFFF800012340007
/// - switch-case table has 4 elements: 0x1000, 0x2000, 0x3000 and 0x4000
/// - the slack space allocated for this handle is at address 0xFFFF800056780000
/// - rax is 1
/// The entire instrumented block would look like this:
/// 0xFFFF800056780000:
///         PUSHFQ
///         PUSH rcx
///         PUSH rax
///         MOV [rsp +  8], 0x5678002F  ; 0xFFFF800056780000 slack address + the size of the header, which is 0x2F
///         MOV [rsp + 12], 0xFFFF8000
///         IMUL rax, rax, 11           ; rax will now be 11
///         ADD [rsp + 8], rax          ; we now have on the stack 0xFFFF80005678002F + 0xB = 0xFFFF80005678003A
///         POP rax
///         POP rcx                     ; ecx will now be 0xFFFF80005678003A
///         MOV [rsp - 8], 0            ; overwrite what used to be the 0xFFFF80005678003A value; this is needed in
///                                     ; order to avoid false-positives in the thread-safeness, which might see this
///                                     ; still pointing inside our slack space, and thus consider unload to be unsafe
///         POPFQ
///         JMP rcx                     ; this jumps to 0xFFFF80005678003A, which is block 1
/// 0x0000BDBDCECE002F:                 ; Block 0, loads the first switch-case value, as immediate
///         MOV ecx, 0x1000
///         JMP 0xFFFF800012340007
/// 0x0000BDBDCECE003A:                 ; Block 1, loads the second switch-case value, as immediate
///         MOV ecx, 0x2000
///         JMP 0xFFFF800012340007
/// 0x0000BDBDCECE0045:                 ; Block 2
///         MOV ecx, 0x3000
///         JMP 0xFFFF800012340007
/// 0x0000BDBDCECE0050:                 ; Block 3
///         MOV ecx, 0x3000
///         JMP 0xFFFF800012340007
/// The MOV instruction at address 0xFFFF800012340000 will be replaced with a "JMP 0xFFFF800056780000" instruction.
///
/// NOTE: the instruction has already been validated by the caller, so there's no need to do any check here.
/// In order to see what validations/checks we do before we decide to relocate such an instruction, take
/// a look at #IntMtblCheckAccess.
/// NOTE: this code will be written inside the guest while the VCPUs are paused.
/// NOTE: after modifying the instruction, its entry inside the  instruction-cache must be invalidated; if we don't
/// do this, another VCPU that might have generated an exit from the same instruction might try to instrument it again,
/// as decoding the current instruction would still see the old MOV cached, instead of seeing the newly patched JMP.
///
/// @param[in, out] Reloc       The mem-table relocation structure.
/// @param[in]      Instrux     Decoded instruction to be instrumented.
/// @param[in]      Regs        The general purpose registers.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the switch-case table has more than 16 entries.
//
{
    INTSTATUS status;
    QWORD slackAddr;
    DWORD tableSize, slackSize, regDst, regIdx, table[MAX_MEM_TABLE_SIZE + 1], cb, rel;
    BYTE code[MAX_MEM_TABLE_SLACK_SIZE], jins[ND_MAX_INSTRUCTION_LENGTH], origins[ND_MAX_INSTRUCTION_LENGTH];
    BOOLEAN inAgent = FALSE;

    // Safe: note that table is DWORD[MAX_MEM_TABLE_SIZE + 1].
    status = IntKernVirtMemRead(Reloc->TableGva, (MAX_MEM_TABLE_SIZE + 1) * 4, table, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    // Extract the table size. Each entry must be a dword RVA inside the NT image. We support max 16 entries per table.
    for (tableSize = 0; tableSize < MAX_MEM_TABLE_SIZE + 1; tableSize++)
    {
        if (table[tableSize] >= gGuest.KernelSize)
        {
            break;
        }
    }

    // Can't reliably get the size, bail out.
    if (tableSize > MAX_MEM_TABLE_SIZE)
    {
        WARNING("[WARNING] Table size at %llx is %d, bailing out.\n", Reloc->TableGva, tableSize);
        return INT_STATUS_NOT_SUPPORTED;
    }

    regDst = Instrux->Operands[0].Info.Register.Reg;
    regIdx = Instrux->Operands[1].Info.Memory.Index;

    slackSize = MEM_TABLE_HEADER_SIZE + MEM_TABLE_ENTRY_SIZE * tableSize;

    slackAddr = IntPtiAllocMemtableSpace(Regs->Rip + Instrux->Length, slackSize);
    if (0 != slackAddr)
    {
        TRACE("[MEMTABLE] We could allocated space in PT filter agent!\n");
        inAgent = TRUE;
    }
    else
    {
        status = IntSlackAlloc(gGuest.KernelVa, FALSE, slackSize, &slackAddr, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSlackAlloc failed: 0x%08x\n", status);
            return status;
        }
    }

    Reloc->InAgent = inAgent;
    Reloc->SlackAddress = slackAddr;
    Reloc->SlackSize = slackSize;

    cb = 0;

    // Store the "PUSHFQ" instruction.
    code[cb++] = 0x9C;

    // Store the "PUSH dst" instruction.
    code[cb++] = 0x48 | (regDst >= 8 ? 0x1 : 0x0);
    code[cb++] = 0x50 | (regDst & 7);

    // Store the "PUSH idx" instruction.
    code[cb++] = 0x48 | (regIdx >= 8 ? 0x1 : 0x0);
    code[cb++] = 0x50 | (regIdx & 7);

    // Overwrite the saved dst with the slack target address.

    // Store the "MOV [rsp + 8], addr low" instruction
    code[cb++] = 0xC7;
    code[cb++] = 0x44;
    code[cb++] = 0x24;
    code[cb++] = 0x08;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 0) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 8) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 16) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 24) & 0xFF;

    // Store the "MOV [rsp + C], addr high" instruction
    code[cb++] = 0xC7;
    code[cb++] = 0x44;
    code[cb++] = 0x24;
    code[cb++] = 0x0C;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 32) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 40) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 48) & 0xFF;
    code[cb++] = ((slackAddr + MEM_TABLE_HEADER_SIZE) >> 56) & 0xFF;

    // Store the "IMUL idx, idx, 11" instruction.
    code[cb++] = 0x48 | (regIdx >= 8 ? 0x5 : 0x0);
    code[cb++] = 0x6B;
    code[cb++] = 0xC0 | (((regIdx & 7) << 3) | (regIdx & 7));
    code[cb++] = MEM_TABLE_ENTRY_SIZE;

    // Store the "ADD [rsp + 8], idx" instruction.
    code[cb++] = 0x48 | (regIdx >= 8 ? 0x4 : 0x0);
    code[cb++] = 0x01;
    code[cb++] = 0x44 | ((regIdx & 7) << 3);
    code[cb++] = 0x24;
    code[cb++] = 0x08;

    // Store the "POP idx" instruction.
    code[cb++] = 0x48 | (regIdx >= 8 ? 0x1 : 0x0);
    code[cb++] = 0x58 | (regIdx & 7);

    // Store the "POP dst" instruction.
    code[cb++] = 0x48 | (regDst >= 8 ? 0x1 : 0x0);
    code[cb++] = 0x58 | (regDst & 7);

    // Store the "MOV [rsp - 8], 0" instruction, which will remove the pointer which may still point inside of us.
    code[cb++] = 0x48;
    code[cb++] = 0xc7;
    code[cb++] = 0x44;
    code[cb++] = 0x24;
    code[cb++] = 0xF8;
    code[cb++] = 0x00;
    code[cb++] = 0x00;
    code[cb++] = 0x00;
    code[cb++] = 0x00;

    // Store the "POPFQ" instruction.
    code[cb++] = 0x9D;

    // Store the "JMP regDst" instruction.
    code[cb++] = 0x40 | ((regDst >= 8) ? 0x1 : 0x0);                // REX prefix.
    code[cb++] = 0xFF;                                              // Opcode.
    code[cb++] = 0xE0 | (regDst & 0x7);                             // Mod R/M, mod 3, reg 4, rm regDst.

    // Store the "MOV regDst, imm/JMP back" stubs.
    for (QWORD i = 0; i < tableSize; i++)
    {
        // Store the "MOV regDst, imm" instruction.
        code[cb++] = 0x40 | ((regDst >= 8) ? 0x1 : 0x0);
        code[cb++] = 0xB8 + (regDst % 8);
        code[cb++] = (table[i] >>  0) & 0xFF;
        code[cb++] = (table[i] >>  8) & 0xFF;
        code[cb++] = (table[i] >> 16) & 0xFF;
        code[cb++] = (table[i] >> 24) & 0xFF;

        if (inAgent)
        {
            // Store the "IRETQ"
            code[cb++] = 0x48;
            code[cb++] = 0xCF;
            // For padding, to make it as long as a "JMP near"
            code[cb++] = 0x90;
            code[cb++] = 0x90;
            code[cb++] = 0x90;
        }
        else
        {
            // Store the "JMP original_code" instruction.
            code[cb++] = 0xE9;
            rel = (DWORD)((gVcpu->Regs.Rip + Instrux->Length) -
                          (slackAddr + MEM_TABLE_HEADER_SIZE + MEM_TABLE_ENTRY_SIZE * (i + 1)));
            code[cb++] = (rel >> 0) & 0xFF;
            code[cb++] = (rel >> 8) & 0xFF;
            code[cb++] = (rel >> 16) & 0xFF;
            code[cb++] = (rel >> 24) & 0xFF;
        }
    }

    if (inAgent)
    {
        // We are using the PT filter agent, we can just INT 20 into it.
        memset(jins, 0x66, sizeof(jins));
        jins[Instrux->Length - 2] = 0xCD;
        jins[Instrux->Length - 1] = 0x14;
    }
    else
    {
        // Patch the instruction with a JMP.
        memset(jins, 0x90, sizeof(jins));
        jins[0] = 0xE9;
        *((DWORD *)&jins[1]) = (DWORD)(slackAddr - (Regs->Rip + 5));
    }

    // Save the old instruction.
    memcpy(origins, Instrux->InstructionBytes, Instrux->Length);

    // Now do the actual patching.
    IntPauseVcpus();

    status = IntMemClkCloakRegion(Regs->Rip, 0, Instrux->Length, MEMCLOAK_OPT_APPLY_PATCH,
                                  origins, jins, NULL, &Reloc->InsCloak);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
        goto _resume_and_exit;
    }

    if (!inAgent)
    {
        status = IntMemClkCloakRegion(slackAddr, 0, slackSize, MEMCLOAK_OPT_APPLY_PATCH,
                                      NULL, code, NULL, &Reloc->SlackCloak);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
            goto _resume_and_exit;
        }
    }
    else
    {
        // No need to use IntVirtMemSafeWrite, as this is a pointer "allocated" by Introcore. Plus, it's EPT protected.
        status = IntKernVirtMemWrite(slackAddr, slackSize, code);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
            goto _resume_and_exit;
        }
    }

    // Flush the RIP address. This is needed because a read violation may be generated for the same RIP
    // for more than one VCPU. The first exit that is handled will also patch the instruction and if the cache
    // is not flushed, the other VCPUs will patch it again (because instead of decoding a jump, they will decode
    // a mov from memory
    status = IntIcFlushAddress(gGuest.InstructionCache, gVcpu->Regs.Rip, IC_ANY_VAS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIcFlushAddress failed: 0x%08x\n", status);
        goto _resume_and_exit;
    }

    Reloc->Patched = TRUE;

    // Indicate that we've patched the instruction.
    status = INT_STATUS_INSTRUCTION_PATCHED;

_resume_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntMtblRemoveEntry(Reloc);
    }

    IntResumeVcpus();

    return status;
}


INTSTATUS
IntMtblCheckAccess(
    void
    )
///
/// @brief Check if the current instruction is like a switch-case table access instruction.
///
/// This function checks if the current instruction (pointed by the RIP on the current VCPU) looks like an
/// instruction which loads switch-case offset from a code-page. We look after the following features:
/// 0. The instruction must be a MOV instruction;
/// 1. The instruction must have exactly 2 operands;
/// 2. First operand must be a register;
/// 3. Second operand must be memory;
/// 4. SIB addressing must be used, with a non-zero index;
/// 5. The memory access must be read;
/// 6. Both operands must be 4 bytes;
/// 7. The instruction must be at least 5 bytes long (in order to accommodate a relative jump);
/// 8. The read linear address must point inside the NT image;
/// 9. The read linear address must not point inside the SSDT;
/// If such a candidate instruction is found, a new entry is allocated for it (or an existing entry is searched).
/// Once we identify the proper entry, we increment the number times the instruction triggered a memory read, and
/// once it exceeds 50 hits, we will try to instrument it using the #IntMtblPatchInstruction function. If
/// instrumenting the instruction fails, we flag the entry as being ignored, and we won't try to instrument it again.
/// NOTE: This function is called on read EPT violations that take place on addresses for which we don't have a
/// registered hook/callback.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If there's no need to instrument the instruction.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    QWORD gva;
    QWORD tableStart;
    BYTE base;
    QWORD disp;
    PIG_ARCH_REGS pRegs;
    PINSTRUX instr;
    LIST_ENTRY *list;
    BOOLEAN foundTable;
    PMEM_TABLE_RELOC pTable;

    if (gGuest.OSType != introGuestWindows)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!gGuest.Guest64)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gVcpu->State != CPU_STATE_EPT_VIOLATION)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pRegs = &gVcpu->Regs;
    gva = gVcpu->Gla;
    instr = &gVcpu->Instruction;
    base = 0;
    disp = 0;
    foundTable = FALSE;
    status = INT_STATUS_SUCCESS;

    if (instr->Instruction != ND_INS_MOV)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Make sure we can reloc this instruction + table.
    if ((instr->OperandsCount != 2) || (instr->Operands[0].Type != ND_OP_REG) ||
        (instr->Operands[1].Type != ND_OP_MEM) || !instr->HasSib ||
        !instr->Operands[1].Info.Memory.HasIndex || (instr->MemoryAccess != ND_ACCESS_READ) ||
        (instr->Operands[0].Size != 4) || (instr->Operands[1].Size != 4) ||
        (instr->Length < 5))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Ignore anything outside the NT image.
    if ((gva < gGuest.KernelVa) || (gva >= gGuest.KernelVa + gGuest.KernelSize) ||
        (pRegs->Rip < gGuest.KernelVa) || (pRegs->Rip >= gGuest.KernelVa + gGuest.KernelSize))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gWinGuest->Ssdt && gWinGuest->NumberOfServices)
    {
        if ((gva >= gWinGuest->Ssdt) &&
            (gva < gWinGuest->Ssdt + ((QWORD)gWinGuest->NumberOfServices * gGuest.WordSize)))
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }

    if (instr->Operands[1].Info.Memory.HasBase)
    {
        base = instr->Operands[1].Info.Memory.Base;
    }

    if (instr->Operands[1].Info.Memory.HasDisp)
    {
        disp = instr->Operands[1].Info.Memory.Disp;
    }

    tableStart = *((QWORD *)pRegs + base) + disp;
    if (tableStart == 0)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        if (pTable->TableGva != tableStart)
        {
            continue;
        }

        foundTable = TRUE;

        ++pTable->Hits;

        if (pTable->Ignored || pTable->Patched)
        {
            continue;
        }

        if (pTable->Hits % 10000 == 0)
        {
            TRACE("[MEMTABLE] Table at %llx accessed for %lld time, from RIP %llx\n",
                  pTable->TableGva, pTable->Hits, pRegs->Rip);
        }

        if (pTable->Hits >= 100000 && !pTable->Dumped)
        {
            ERROR("[ERROR] Table at %llx accessed too many times (%lld), from RIP %llx, event %lld\n",
                  pTable->TableGva, pTable->Hits, pRegs->Rip, gEventId);

            IntDisasmGva(pRegs->Rip, ND_MAX_INSTRUCTION_LENGTH);
            IntDumpGvaEx(pTable->TableGva, MAX_MEM_TABLE_SIZE, 0, 16, 4, TRUE, FALSE);

            pTable->Dumped = TRUE;
        }

        if (pTable->Hits >= 50 && (!gGuest.BootstrapAgentAllocated || IntPtiGetAgentAddress()))
        {
            // Try to patch this instruction. Note that we won't relocate the instruction and table if the bootstrap
            // agent is active, because we would generate slack holes when we would free the it.
            status = IntMtblPatchInstruction(pTable, instr, pRegs);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntMemTablesPatchInstruction failed: 0x%08x\n", status);

                pTable->Ignored = TRUE;
            }
            else
            {
                CHAR text[ND_MIN_BUF_SIZE];

                NdToText(instr, pRegs->Rip, sizeof(text), text);

                LOG("[MEMTABLE] [%d] Successfully patched instruction %llx:%s, will return 0x%x\n",
                    gVcpu->Index, pRegs->Rip, text, status);
            }
        }

        break;
    }

    if (foundTable)
    {
        return status;
    }

    pTable = HpAllocWithTag(sizeof(*pTable), IC_TAG_MTBL);
    if (NULL == pTable)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pTable->Rip = pRegs->Rip;
    pTable->Hits = 1;
    pTable->TableGva = tableStart;

    InsertTailList(&gMemTables, &pTable->Link);

    return status;
}


BOOLEAN
IntMtblIsPtrInReloc(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ QWORD *Table
    )
///
/// @brief Check if the given pointer is inside a mem-table relocation handler.
///
/// @param[in]  Ptr     The pointer to be checked.
/// @param[in]  Type    Pointer type - stack value or live RIP.
/// @param[out] Table   Optional address to the relocation table, if any is found.
///
/// @retval TRUE If the pointer points within a relocation handler, FALSE otherwise.
///
{
    LIST_ENTRY *list;

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        PMEM_TABLE_RELOC pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        if ((Ptr >= pTable->SlackAddress) && (Ptr < pTable->SlackAddress + pTable->SlackSize))
        {
            WARNING("[WARNING] Found %s ptr 0x%016llx in memtable relocs: slack addr 0x%016llx, "
                    "instruction addr 0x%016llx\n",
                    Type == ptrLiveRip ? "live RIP" : "stack value", Ptr, pTable->SlackAddress, pTable->Rip);

            if (NULL != Table)
            {
                *Table = pTable->TableGva;
            }

            return TRUE;
        }
    }

    if (NULL != Table)
    {
        *Table = 0;
    }

    return FALSE;
}


void
IntMtblDisable(
    void
    )
///
/// @brief Disables mem-table instructions instrumentation.
///
/// This function will remove all the hooks placed on mem-table like instructions, thus disabling the
/// instrumentation. Note that the handlers will still remain, and if we have pointers still pointing there,
/// nothing bad will happen. This function should be called only when preparing for uninit.
///
{
    LIST_ENTRY *list;

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        PMEM_TABLE_RELOC pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        if (pTable->InsCloak)
        {
            IntMemClkUncloakRegion(pTable->InsCloak, MEMCLOAK_OPT_APPLY_PATCH);

            pTable->InsCloak = NULL;

            // Flush the icache entry.
            IntIcFlushAddress(gGuest.InstructionCache, pTable->Rip, IC_ANY_VAS);
        }
    }
}


BOOLEAN
IntMtblInsRelocated(
    _In_ QWORD Rip
    )
///
/// @brief Check if the instruction at the provided RIP is instrumented.
///
/// @param[in]  Rip The RIP to be checked.
///
/// @retval TRUE if the RIP contains an instrumented instruction, FALSE otherwise.
///
{
    LIST_ENTRY *list;

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        PMEM_TABLE_RELOC pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        if (pTable->Rip == Rip)
        {
            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntMtblRemoveAgentEntries(
    void
    )
///
/// @brief Removes only the mem-table entries that were relocated inside the PT filter.
///
/// When using the PT filter, many mem-table instructions may need to be instrumented. Since the NT sections
/// slack space is very scarce, we will use, in that case, the PT filter itself in order to accommodate the
/// relocated instructions. However, when the PT filter is unloaded, we also must stop instrumenting
/// the instructions that were relocated inside of it.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    LIST_ENTRY *list;

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        PMEM_TABLE_RELOC pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        if (pTable->InAgent)
        {
            // No need to pause here, uninit functions are called with all the VCPUs paused.
            IntMtblRemoveEntry(pTable);

            RemoveEntryList(&pTable->Link);

            HpFreeAndNullWithTag(&pTable, IC_TAG_MTBL);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntMtblUninit(
    void
    )
///
/// @brief Completely uninit the mem-tables, removing all the handlers from the NT slack space.
///
/// This function must be called only during uninit, and only after thread-safeness was employed, in order to make
/// sure no live RIPs or saved RIPs point inside a handler.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PMEM_TABLE_RELOC pTable;
    LIST_ENTRY *list;

    list = gMemTables.Flink;
    while (list != &gMemTables)
    {
        pTable = CONTAINING_RECORD(list, MEM_TABLE_RELOC, Link);
        list = list->Flink;

        LOG("[MEMTABLE] Table at %llx accessed for %lld time, from RIP %llx, ignored = %d\n",
            pTable->TableGva, pTable->Hits, pTable->Rip, pTable->Ignored);

        // No need to pause here, uninit functions are called with all the VCPUs paused.
        IntMtblRemoveEntry(pTable);

        RemoveEntryList(&pTable->Link);

        HpFreeAndNullWithTag(&pTable, IC_TAG_MTBL);
    }

    return INT_STATUS_SUCCESS;
}
