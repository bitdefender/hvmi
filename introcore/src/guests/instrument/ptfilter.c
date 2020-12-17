/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ptfilter.h"
#include "ptfilter.h"
#include "winagent.h"
#include "decoder.h"
#include "hook.h"
#include "icache.h"
#include "kernvm.h"
#include "loader.h"
#include "memcloak.h"
#include "memtables.h"
#include "winagent_ptdriver_x64.h"
#include "winapi.h"
#include "winpe.h"
#include "winpower.h"


///
/// @file ptfilter.c
///
/// @brief This is the main instrumentation file, which scans, identifies and instruments NT instructions that
/// have the potential to be used as page-table writes.
///
/// PT filter is an instrumentation mechanism used to intercept all memory write instruction that have the
/// potential of writing to a page-table entry. Initially, we will scan NT image (.text section, more specifically)
/// in order to find candidate instructions. Once candidate instructions are identified, they are replaced with a
/// breakpoint (INT3, encoding 0xCC) instruction. When this breakpoint is hit, a VM exit to Introcore will take
/// place. Introcore will then analyze the instruction operands, and determine whether it is a page-table
/// modification or not. If the instruction is deemed to be e regular memory operation and not a page-table write,
/// then it will simply be restored. Instruction which exhibit page-table write behavior will be replaced with an
/// "INT 20" instruction that will divert code execution inside our filtering agent, which will analyze the
/// instruction and decide whether it does a relevant page-table modification or not. A hyper call (VMCALL) will
/// be issued if such a relevant modification is done.
/// While the PT filter is enabled, the page-tables will not be write-hooked inside the EPT. This mechanism is used
/// mostly for debugging purposes, as writes that do not originate inside the NT will pass through and will not
/// be intercepted at all.
/// For more information regarding the components of the PT filter, take a look at prfilter64.asm.
// The main components are:
/// 1. A table of handler. For each instruction that modifies a page-table entry, we will store its handler address
///    inside this table.
/// 2. Section of handlers. This contains the actual code handlers for each instrumented instruction.
/// 3. Cache. This contains all the guest physical pages the PT filter doesn't have to generate a VM exit, since
///    they represent unmonitored pages.
/// 4. Mem-tables. A section reserved for mem-tables.
/// 5. The main check function. This function checks if an accessed linear address is a page table or not; if it
///    is, it places the global lock and continues handling, otherwise it resumes execution.
/// 6. The main handler. This generically handles page-table entry modifications.
/// 7. Entry point. This is the code that gets executed when an INT 20 is executed; this code simply takes the
///    RIP from the interrupt frame and tries to locate an appropriate handler inside the handler table.
///


#define MAX_ENTRIES_PER_BUCKET      256
#define MAX_LUT_PAGES               64
#define MAX_HANDLER_SIZE            48ull
#define TABLE_BUCKET_MASK           0x3F


///
/// Describes a PT write candidate instruction.
///
typedef struct _PTI_CANDIDATE
{
    LIST_ENTRY  Link;           ///< List entry element.
    RBNODE      Node;           ///< RB node for this entry.
    QWORD       Gla;            ///< Linear address where the candidate was found.
    INSTRUX     Instruction;    ///< The decoded instruction.
    void       *CloakHandle;    ///< Cloak handle used to hide the INT3/INT 20.
    BOOLEAN     Monitored;      ///< TRUE if the instruction is being monitored. FALSE if it has been restored.
    BOOLEAN     PtInstruction;  ///< TRUE if the instruction modified e PT entry.
} PTI_CANDIDATE, *PPTI_CANDIDATE;

/// Indicate the PT filter state.
BOOLEAN gPtMonitored, gPtPendingRemove, gPtDeployed, gPtPendingInject, gPtEnableMonitor;

QWORD gPtDriverAddress;         ///< Guest virtual address where the PT filter was injected.
DWORD gPtDriverSize;            ///< Size of the PT filter.
DWORD gPtDriverEntryPoint;      ///< Entry point of the PT filter.
QWORD gPtDriverCacheAddress;    ///< GVA of the PT filter cache - entries we do not need to generate an exit for.
QWORD gPtDriverTableAddress;    ///< Table of handlers inside the PT filter.
QWORD gPtDriverHandlersAddress; ///< Main handler inside the PT filter.
QWORD gPtDriverMainAddress;     ///< Main function inside the PT filter.
QWORD gPtDriverRdataAddress;    ///< Address of the rdata section inside the PT filter.
QWORD gPtDriverMemtableAddress; ///< Section used to store mem-tables (checkout memtables.c).
QWORD gPtDriverCheckFunction;   ///< The check function inside the PT filter.

PBYTE gPtDriverImage;           ///< Pointer to the PT filter image.
void *gPtDriverHook;            ///< PT filter hook handle.
void *gPtDriverCloak;           ///< PT filter cloak handle.

DWORD gPtHandlerIndex;          ///< Current handler index.
DWORD gPtTableIndexes[MAX_LUT_PAGES];   ///< Lookup table of indexes.

// Relevant section sizes.
DWORD gPtMemtableSize;          ///< This indicates how much mem-table space we have allocated.
DWORD gPtMemtableTotalSize;     ///< Total mem-table size.
DWORD gPtHandlersTotalSize;     ///< Total handlers size.



_Function_class_(FUNC_RbTreeNodeFree) static void
IntPtiRbTreeNodeFree(
    _Inout_ RBNODE *Node
    )
///
/// @brief Called on RB tree node free.
///
/// @param[in, out] Node    The node to be freed.
///
{
    UNREFERENCED_PARAMETER(Node);
}


_Function_class_(FUNC_RbTreeNodeCompare) static int
IntPtiRbTreeNodeCompareRip(
    _In_ RBNODE *Left,
    _In_ RBNODE *Right
    )
///
/// @brief RB tree node compare function.
///
/// @param[in]  Left    The left node.
/// @param[in]  Right   The right node.
///
/// @retval -1 If the left node is smaller than the right node.
/// @retval  0 If the left node is equal to the right node.
/// @retval +1 If the left node is larger than the right node.
///
{
    PPTI_CANDIDATE p1 = CONTAINING_RECORD(Left, PTI_CANDIDATE, Node);
    PPTI_CANDIDATE p2 = CONTAINING_RECORD(Right, PTI_CANDIDATE, Node);

    if (p1->Gla < p2->Gla)
    {
        return -1;
    }
    else if (p1->Gla > p2->Gla)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


/// We store each candidate in a RB tree, ordered by the location. We also store them in a linked-list, for convenience.
LIST_HEAD gPtiCandidatesList = LIST_HEAD_INIT(gPtiCandidatesList);

/// PT candidate instruction RB tree root.
RBTREE gPtiCandidatesTree = RB_TREE_INIT(gPtiCandidatesTree, IntPtiRbTreeNodeFree, IntPtiRbTreeNodeCompareRip);



static void
IntPtiResetState(
    void
    )
///
/// @brief Reset the PT filter state (used after removing it from guest memory).
///
{
    gPtPendingRemove = gPtDeployed = gPtPendingInject = gPtEnableMonitor = FALSE;
    gPtDriverAddress = 0;
    gPtDriverCacheAddress = 0;
    gPtDriverTableAddress = 0;
    gPtDriverHandlersAddress = 0;
    gPtDriverMainAddress = 0;
    gPtDriverRdataAddress = 0;
    gPtDriverMemtableAddress = 0;
    gPtDriverCheckFunction = 0;
    gPtDriverEntryPoint = 0;
    gPtDriverSize = 0;
    gPtMemtableSize = 0;
    gPtHandlerIndex = 0;
    memset(gPtTableIndexes, 0, sizeof(gPtTableIndexes));
}


static void
IntPtiDeleteInstruction(
    _Inout_ PPTI_CANDIDATE Candidate
    )
///
/// @brief Delete a PT candidate instruction.
///
/// @param[in, out] Candidate   The candidate instruction to delete.
///
{
    if (NULL != Candidate->CloakHandle)
    {
        IntMemClkUncloakRegion(Candidate->CloakHandle, MEMCLOAK_OPT_APPLY_PATCH);

        IntIcFlushAddress(gGuest.InstructionCache, Candidate->Gla, IC_ANY_VAS);
    }

    Candidate->CloakHandle = NULL;

    RemoveEntryList(&Candidate->Link);

    RbDeleteNode(&gPtiCandidatesTree, &Candidate->Node);

    HpFreeAndNullWithTag(&Candidate, IC_TAG_ALLOC);
}


static INTSTATUS
IntPtiMonitorAllPtWriteCandidates(
    void
    )
///
/// @brief Scan the .text section of the NT image for PT candidates.
///
/// This function will iterate through the entire .text section of the NT image, and search for viable PT candidates.
/// An instruction is considered a PT candidate if it is one of the following:
/// - mov qword [reg{+disp}], 0
/// - mov qword [reg{+disp}], reg
/// - xchg qword [reg{+disp}], reg
/// - lock cmpxchg [reg{+disp}], reg
/// - base reg cannot be RSP
/// - displacement, if present:
///      - must be less than 0x20
///      - must be aligned to 8
/// Once a candidate is identified, it is replaced with an INT3, in order to intercept its first execution following
/// guest re-entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    IMAGE_SECTION_HEADER sec;
    INSTRUX instrux;
    DWORD i, vi, count, seci, pagei;
    BYTE int3[16] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    CHAR secname[9];
    PPTI_CANDIDATE pPtc;
    PBYTE pPage1, pPage2;

    // NOTE: The VCPUs must already be paused when calling this.
    pPage1 = pPage2 = NULL;

    STATS_ENTER(statsPtsFilterInsSearch);

    for (seci = 0; ; seci++)
    {
        DWORD pageCount;

        // Determine the .text section size & location.
        status = IntPeGetSectionHeaderByIndex(gGuest.KernelVa, gWinGuest->KernelBuffer, seci, &sec);
        if (!INT_SUCCESS(status))
        {
            break;
        }

        // We only parse executable, non-paged, non-discardable sections.
        if (0 == (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            0 == (sec.Characteristics & IMAGE_SCN_MEM_NOT_PAGED) ||
            0 != (sec.Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            continue;
        }

        if (0 != memcmp(sec.Name, ".text", 5))
        {
            // Skip all non-.text sections.
            continue;
        }

        memcpy(secname, sec.Name, 8);
        secname[8] = 0;

        TRACE("[PTCORE] Parsing section '%s'...\n", secname);

        // Will count how many valid, consecutive instructions we have found. We will ignore candidate instructions
        // if they are not preceded by at least 8 such valid, consecutive instructions.
        vi = count = i = 0;

        pageCount = ROUND_UP(sec.Misc.VirtualSize, PAGE_SIZE) / PAGE_SIZE;

        // Start disassembling the .text section.
        for (pagei = 0; pagei < pageCount; ++pagei)
        {
            DWORD offset = sec.VirtualAddress + pagei * PAGE_SIZE;
            DWORD sizeToParse = (pagei == (pageCount - 1)) ? sec.Misc.VirtualSize & PAGE_OFFSET : PAGE_SIZE;
            QWORD target = gGuest.KernelVa + offset;

            if (NULL == pPage1)
                // We may have already mapped this inside the while loop
            {
                status = IntVirtMemMap(target, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage1);
                if (!INT_SUCCESS(status))
                {
                    ERROR("ERROR] Failed mapping page %d of section %d: 0x%08x\n", pagei, seci, status);
                    goto cleanup_and_exit;
                }
            }

            pPage2 = NULL;

            while (i < sizeToParse)
            {
                BOOLEAN bCrossPage = FALSE;
                NDSTATUS ndstatus = NdDecodeEx(&instrux,
                                               pPage1 + i,
                                               sizeToParse - i,
                                               ND_CODE_64,
                                               ND_DATA_64);
                if (ND_STATUS_BUFFER_TOO_SMALL == ndstatus)
                {
                    BYTE buffer[16] = { 0 };

                    bCrossPage = TRUE;

                    status = IntVirtMemMap(target + PAGE_SIZE, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage2);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("ERROR] Failed mapping page %d of section %d: 0x%08x\n", pagei, seci, status);
                        goto cleanup_and_exit;
                    }

                    memcpy(buffer, pPage1 + i, sizeToParse - i);
                    memcpy(buffer + sizeToParse - i, pPage2, 16 - (sizeToParse - i));

                    status = IntDecDecodeInstructionFromBuffer(buffer, 16, IG_CS_TYPE_64B, &instrux);
                }
                else
                {
                    status = ND_SUCCESS(ndstatus) ? INT_STATUS_SUCCESS : INT_STATUS_DISASM_ERROR;
                }

                if (!INT_SUCCESS(status))
                {
                    i++;
                    vi = 0;
                }
                else
                {
                    // Note: none of these have single byte encodings (with memory access) - this is important, because
                    // e we will replace them with INT 20 (2 bytes), so we won't overwrite two instructions.
                    // Instruction formats accepted:
                    // mov qword [reg{+disp}], 0
                    // mov qword [reg{+disp}], reg
                    // xchg qword [reg{+disp}], reg
                    // lock cmpxchg [reg{+disp}], reg
                    // Constraints:
                    // - base reg cannot be RSP
                    // - disp, if present:
                    //      - must be less than 0x20
                    //      - must be aligned to 8
                    if (instrux.Instruction == ND_INS_MOV ||
                        instrux.Instruction == ND_INS_XCHG ||
                        (instrux.Instruction == ND_INS_CMPXCHG && instrux.HasLock))
                    {
                        if (instrux.Operands[0].Type == ND_OP_MEM && instrux.Operands[0].Size == 8 &&
                            instrux.Operands[0].Info.Memory.HasBase && !instrux.Operands[0].Info.Memory.HasIndex &&
                            instrux.Operands[0].Info.Memory.Base != NDR_RSP &&
                            (!instrux.HasDisp || ((instrux.Displacement < 0x20) && (instrux.Displacement % 8 == 0))) &&
                            ((instrux.Operands[1].Type == ND_OP_REG) || ((instrux.Operands[1].Type == ND_OP_IMM) &&
                                                                    (instrux.Operands[1].Info.Immediate.Imm == 0))) &&
                            (vi >= 8))
                        {
                            pPtc = HpAllocWithTag(sizeof(*pPtc), IC_TAG_ALLOC);
                            if (NULL == pPtc)
                            {
                                status = INT_STATUS_INSUFFICIENT_RESOURCES;
                                goto cleanup_and_exit;
                            }

                            pPtc->Gla = target + i;

                            memcpy(&pPtc->Instruction, &instrux, sizeof(instrux));

                            // Intercept the instruction.
                            status = IntMemClkCloakRegion(pPtc->Gla,
                                                          0,
                                                          pPtc->Instruction.Length,
                                                          0,
                                                          pPtc->Instruction.InstructionBytes,
                                                          int3,
                                                          NULL,
                                                          &pPtc->CloakHandle);
                            if (!INT_SUCCESS(status))
                            {
                                ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
                                HpFreeAndNullWithTag(&pPtc, IC_TAG_ALLOC);
                                goto cleanup_and_exit;
                            }

                            if (!bCrossPage)
                            {
                                memcpy(pPage1 + i, int3, instrux.Length);
                            }
                            else
                            {
                                memcpy(pPage1 + i, int3, sizeToParse - i);
                                memcpy(pPage2, int3, instrux.Length - (sizeToParse - i));
                            }

                            status = RbInsertNode(&gPtiCandidatesTree, &pPtc->Node);
                            if (!INT_SUCCESS(status))
                            {
                                ERROR("[ERROR] RbInsertNode failed: 0x%08x\n", status);
                                HpFreeAndNullWithTag(&pPtc, IC_TAG_ALLOC);
                                goto cleanup_and_exit;
                            }

                            InsertTailList(&gPtiCandidatesList, &pPtc->Link);

                            IntIcFlushAddress(gGuest.InstructionCache, pPtc->Gla, IC_ANY_VAS);

                            pPtc->Monitored = TRUE;

                            count++;
                        }
                    }

                    vi++;
                    i += instrux.Length;
                }
            }

            i -= sizeToParse;

            IntVirtMemUnmap(&pPage1);

            pPage1 = pPage2;
            pPage2 = NULL;
        }

        TRACE("[PTCORE] Patched %d instructions in section '%s'!\n", count, secname);
    }

    gPtMonitored = TRUE;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    if (NULL != pPage1)
    {
        IntVirtMemUnmap(&pPage1);
    }

    if (NULL != pPage2)
    {
        IntVirtMemUnmap(&pPage2);
    }

    STATS_EXIT(statsPtsFilterInsSearch);

    return status;
}


static INTSTATUS
IntPtiRestoreAllPtWriteCandidates(
    void
    )
///
/// @brief Restore all PT candidates, by removing the INT3/INT 20 hook established on them.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    // Search for the matching instruction.
    for (LIST_ENTRY *list = gPtiCandidatesList.Flink; list != &gPtiCandidatesList; )
    {
        PPTI_CANDIDATE pPtc = CONTAINING_RECORD(list, PTI_CANDIDATE, Link);

        list = list->Flink;

        IntPtiDeleteInstruction(pPtc);
    }

    gPtMonitored = FALSE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiInspectInstruction(
    PPTI_CANDIDATE Candidate
    )
///
/// @brief Inspect a candidate instruction for page-table modifications.
///
/// This function is called whenever a breakpoint that was set on a PT candidate instruction is hit. In order
/// to determine if the instruction is page-table modifying, we employ the following checks:
/// 1. The PML4 index is the same as the self-map index (recursive page-table reference);
/// 2. It translates to a currently known page-table;
/// 3. The written value looks like a legit page-table entry
/// If such a relevant modification is identified, the following handling code will be used for the instruction:
///         PUSH    0/1         ; Save the state of the IF flag, as it was when the instruction executed.
///         PUSH    disp        ; The displacement used by the memory instruction.
///         PUSH    gla         ; This saves the gla (base register) as used by the memory instruction.
///         CALL    check       ; Call the main check function, which determines if the gla is PT or not.
/// ; If the above call returns, the instruction can be further processed, as it means it's a PT instruction.
///         PUSH    [gla]       ; Save old PT entry value.
///         Original instruction
///         PUSH    [gla]       ; Save new PT entry value.
///         JMP     main        ; Jumps to the main handler.
/// NOTE: When the check function return, it also places a global lock. This is needed, in order to avoid
/// TOCTOU races with other VCPUs that might modify the same PT entry.
/// NOTE: The lock will be released by the main function, before returning to the NT code.
/// After building this handler, the address of the handler will be installed inside the handlers section
/// of the PT filter, and the handler code will be written inside the PT filter. The old INT3 will now be
/// replaced with an "INT 20": each time an "INT 20" takes place, the PT filter handler will locate the
/// adequate handler inside the handlers table, and call it. Note that this is required, since each instruction
/// will be handled differently.
///
/// @param Candidate    The candidate instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD addr = *(&gVcpu->Regs.Rax + Candidate->Instruction.Operands[0].Info.Memory.Base) +
                 Candidate->Instruction.Operands[0].Info.Memory.Disp; // Will be 0 if not present.
    BYTE int20[16] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xCD, 0x14 };
    BYTE handler[MAX_HANDLER_SIZE], i, len;
    BOOLEAN relevant;
    QWORD rip, hnd;
    DWORD dest;
    QWORD idx;
    enum { ptNone, ptSelfMap, ptTranslatesToPt, ptWritesPte } criteria = ptNone;

    IntPauseVcpus();

    // Assume the modification is not relevant for now.
    relevant = FALSE;

    // The most important and straight forward criteria - a self-map entry is being accessed.
    if (((addr >> 39) & 0x1FF) == gGuest.Mm.SelfMapIndex)
    {
        relevant = TRUE;
        criteria = ptSelfMap;
    }

#define REG(r)      (*(&gVcpu->Regs.Rax + (r)))

    // Not a self-map entry - see if this translates to a PT anyway.
    if (!relevant)
    {
        PHOOK_EPT_ENTRY pageEntry = NULL;
        QWORD gpa, gla;

        // NOTE: We only instrument instructions using register base addressing + optional displacement (max 0x20).
        gla = REG(Candidate->Instruction.Operands[0].Info.Memory.Base) +
              Candidate->Instruction.Operands[0].Info.Memory.Disp;

        // Translate the GLA.
        status = IntTranslateVirtualAddress(gla, gVcpu->Regs.Cr3, &gpa);
        if (INT_SUCCESS(status))
        {
            pageEntry = IntHookGpaGetExistingEptEntry(gpa);
            if (NULL != pageEntry)
            {
                // Check if this is a page table.
                relevant = pageEntry->PtCount != 0;
                criteria = ptTranslatesToPt;
            }
        }
    }

    // Not a PT accessed at all - maybe an unmonitored PT, without self-map access, so check if the written value
    // looks like a legit PT entry.
    if (!relevant)
    {
        QWORD newval;

        if (ND_OP_REG == Candidate->Instruction.Operands[1].Type)
        {
            newval = REG(Candidate->Instruction.Operands[1].Info.Register.Reg);
        }
        else if (ND_OP_IMM == Candidate->Instruction.Operands[1].Type)
        {
            newval = Candidate->Instruction.Operands[1].Info.Immediate.Imm;
        }
        else
        {
            // This wont match anything.
            newval = 0;
        }

        // We take a look at the low 12 bits, and match them against a few known PT values.
        // We take a look at the high 12 bit, which must resemble legit PT values.
        // We take a look at the mapping bits, which must not be 0.
        if (((newval & 0xFFF) == 0x863 || (newval & 0xFFF) == 0x063 ||
             (newval & 0xFFF) == 0x8E3 || (newval & 0xFFF) == 0x021) &&
            ((newval & 0xFFF0000000000000) == 0x0000000000000000 ||
             (newval & 0xFFF0000000000000) == 0x0A00000000000000 ||
             (newval & 0xFFF0000000000000) == 0x8A00000000000000) &&
            ((newval & 0x000FFFFFFFFFF000) != 0))
        {
            relevant = TRUE;
            criteria = ptWritesPte;
        }
    }

    // Check for self-map - we use the PML4 index for that.
    if (relevant)
    {
        // We always use the instruction following the current one, since its easier.
        rip = Candidate->Gla + Candidate->Instruction.Length;

        // Make sure we still have space left inside the handlers section.
        if (gPtHandlerIndex >= gPtHandlersTotalSize / MAX_HANDLER_SIZE)
        {
            ERROR("[ERROR] Maximum handler index reached!\n");
            IntEnterDebugger();
            goto release_and_exit;
        }

        // Make sure we still have space left inside the (rip, hnd) table. Max MAX_ENTRIES_PER_BUCKET entries per page.
        idx = gPtTableIndexes[rip & TABLE_BUCKET_MASK];
        if (idx >= MAX_ENTRIES_PER_BUCKET)
        {
            ERROR("[ERROR] Maximum table index reached for bucket %lld!\n", rip & TABLE_BUCKET_MASK);
            IntEnterDebugger();
            goto release_and_exit;
        }

        len = 0;

        // Build the "PUSH IF" instruction.
        handler[len++] = 0x6A;
        handler[len++] = (gVcpu->Regs.Flags & NDR_RFLAG_IF) ? 1 : 0;

        // Build the "PUSH disp" instruction.
        handler[len++] = 0x6A;
        if (Candidate->Instruction.HasDisp)
        {
            // NOTE: We already made sure the displacement is less than 0x20, so it fits in a single byte.
            handler[len++] = (BYTE)Candidate->Instruction.Displacement;
        }
        else
        {
            handler[len++] = 0;
        }

        // Build the "PUSH gla" instruction.
        handler[len++] = 0x48 | Candidate->Instruction.Rex.b;
        handler[len++] = 0x50 | Candidate->Instruction.ModRm.rm;

        // Build the "CALL check" instruction.
        dest = (DWORD)(gPtDriverCheckFunction -
            (gPtDriverHandlersAddress + (gPtHandlerIndex * MAX_HANDLER_SIZE) + len + 5));

        // Store a call to the check function.
        handler[len++] = 0xE8;
        handler[len++] = (dest >> 0x00) & 0xFF;
        handler[len++] = (dest >> 0x08) & 0xFF;
        handler[len++] = (dest >> 0x10) & 0xFF;
        handler[len++] = (dest >> 0x18) & 0xFF;

        // If the above call returns, we can proceed with the instruction.

        // Build the "PUSH qword [gla]" instruction.
        handler[len++] = 0x48 | Candidate->Instruction.Rex.b;
        handler[len++] = 0xFF;
        handler[len++] = 0x30 | Candidate->Instruction.ModRm.rm | (Candidate->Instruction.ModRm.mod << 6);

        if (Candidate->Instruction.HasSib)
        {
            handler[len++] = Candidate->Instruction.Sib.Sib;
        }

        if (Candidate->Instruction.HasDisp)
        {
            for (QWORD k = 0; k < Candidate->Instruction.DispLength; k++)
            {
                handler[len++] = (Candidate->Instruction.Displacement >> (k * 8)) & 0xFF;
            }
        }

        // Store the original instruction.
        for (i = 0; i < Candidate->Instruction.Length; i++)
        {
            handler[len++] = Candidate->Instruction.InstructionBytes[i];
        }

        // Store the "PUSH qword [gla]" instruction.
        handler[len++] = 0x48 | Candidate->Instruction.Rex.b;
        handler[len++] = 0xFF;
        handler[len++] = 0x30 | Candidate->Instruction.ModRm.rm | (Candidate->Instruction.ModRm.mod << 6);

        if (Candidate->Instruction.HasSib)
        {
            handler[len++] = Candidate->Instruction.Sib.Sib;
        }

        if (Candidate->Instruction.HasDisp)
        {
            for (QWORD k = 0; k < Candidate->Instruction.DispLength; k++)
            {
                handler[len++] = (Candidate->Instruction.Displacement >> (k * 8)) & 0xFF;
            }
        }

        // Right here, the stack layout is:
        // IF indicator (1 if IF is set when the instruction normally executes, 0 otherwise)
        // The instruction displacement
        // The instruction base GLA
        // Old value
        // New value

        // Store the "JMP main handler" instruction.
        dest = (DWORD)(gPtDriverMainAddress -
            (gPtDriverHandlersAddress + (gPtHandlerIndex * MAX_HANDLER_SIZE) + len + 5));

        // Store a jump to the main cache handler.
        handler[len++] = 0xE9;
        handler[len++] = (dest >> 0x00) & 0xFF;
        handler[len++] = (dest >> 0x08) & 0xFF;
        handler[len++] = (dest >> 0x10) & 0xFF;
        handler[len++] = (dest >> 0x18) & 0xFF;

        // Modify the table to hold the new entry.

        hnd = gPtDriverHandlersAddress + ((QWORD)gPtHandlerIndex * MAX_HANDLER_SIZE);

        // No need to use IntVirtMemSafeWrite, since we already used it to deliver the agent at this address, so if that
        // worked, these will work too.

        status = IntKernVirtMemWrite(gPtDriverTableAddress + ((rip & TABLE_BUCKET_MASK) << 12) + idx * 16, 8, &rip);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
            IntEnterDebugger();
            goto release_and_exit;
        }

        status = IntKernVirtMemWrite(gPtDriverTableAddress + ((rip & TABLE_BUCKET_MASK) << 12) + idx * 16 + 8, 8, &hnd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
            IntEnterDebugger();
            goto release_and_exit;
        }

        // Store the actual handler code.
        status = IntKernVirtMemWrite(gPtDriverHandlersAddress + gPtHandlerIndex * MAX_HANDLER_SIZE, len, handler);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
            IntEnterDebugger();
            goto release_and_exit;
        }

        // Store an INT20 there.
        status = IntMemClkModifyPatchedData(Candidate->CloakHandle, 0, Candidate->Instruction.Length,
                                            &int20[16 - Candidate->Instruction.Length]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkModifyPatchedData failed: 0x%08x\n", status);
            IntEnterDebugger();
            goto release_and_exit;
        }

        gPtHandlerIndex++;
        gPtTableIndexes[rip & TABLE_BUCKET_MASK]++;

        Candidate->PtInstruction = TRUE;
        Candidate->Monitored = FALSE;

        // We modified the instruction, so flush it now.
        IntIcFlushAddress(gGuest.InstructionCache, Candidate->Gla, IC_ANY_VAS);

        TRACE("[PTCORE] Successfully patched instruction at RIP 0x%016llx, HND 0x%016llx, index %d, criteria %d!\n",
              Candidate->Gla, hnd, gPtHandlerIndex, criteria);
    }
    else
    {
        // We can delete all instructions which are not viable candidates.
        IntPtiDeleteInstruction(Candidate);
    }

release_and_exit:
    IntResumeVcpus();

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPtiRemoveInstruction(
    _In_ QWORD Rip
    )
///
/// @brief Remove the hook on a monitored instruction.
///
/// @param[in]  Rip The RIP of the instruction to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If PT monitoring is not enabled.
///
{
    LIST_ENTRY *list;

    if (!gPtMonitored)
    {
        return INT_STATUS_NOT_FOUND;
    }

    list = gPtiCandidatesList.Flink;
    while (list != &gPtiCandidatesList)
    {
        PTI_CANDIDATE *pPtc = CONTAINING_RECORD(list, PTI_CANDIDATE, Link);
        QWORD oldiret = 0;
        INTSTATUS status;

        list = list->Flink;

        // We store the address as saved by INT 20 in R9, so the address immediately after the instruction.
        if (pPtc->Gla + pPtc->Instruction.Length == Rip)
        {
            LOG("[PTCORE] Found instruction to remove, RIP 0x%016llx\n", pPtc->Gla);

            IntDumpGva(gVcpu->Regs.Rsp, 0x80, gVcpu->Regs.Cr3);

            // Patch the return address of the IRETQ instruction so it points to the old instruction.
            status = IntKernVirtMemRead(gVcpu->Regs.Rsp + 0x50, sizeof(oldiret), &oldiret, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
                IntEnterDebugger();
            }

            oldiret -= pPtc->Instruction.Length;

            status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                         gVcpu->Regs.Rsp + 0x50,
                                         sizeof(oldiret),
                                         &oldiret,
                                         IG_CS_RING_0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
                IntEnterDebugger();
            }

            IntPtiDeleteInstruction(pPtc);

            break;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPtiHandleInt3(
    void
    )
///
/// @brief This function is the main INT3 handler.
///
/// This function simply searches for the instruction that has been monitored at the current RIP, and calls
/// the inspection function on it, #IntPtiInspectInstruction.
///
/// @retval #INT_STATUS_NOT_FOUND If an instruction has not been monitored at current RIP.
/// @retval #INT_STATUS_NO_DETOUR_EMU If an instruction was found.
///
{
    INTSTATUS status;
    PTI_CANDIDATE target;
    RBNODE *result;
    PPTI_CANDIDATE pPtc;

    if (!gPtMonitored)
    {
        return INT_STATUS_NOT_FOUND;
    }

    STATS_ENTER(statsPtsFilterInt3);

    target.Gla = gVcpu->Regs.Rip;

    status = RbLookupNode(&gPtiCandidatesTree, &target.Node, &result);
    if (!INT_SUCCESS(status))
    {
        STATS_EXIT(statsPtsFilterInt3);
        return INT_STATUS_NOT_FOUND;
    }

    pPtc = CONTAINING_RECORD(result, PTI_CANDIDATE, Node);

    if (pPtc->Monitored)
    {
        IntPtiInspectInstruction(pPtc);
    }

    STATS_EXIT(statsPtsFilterInt3);

    return INT_STATUS_NO_DETOUR_EMU;
}


void
IntPtiDumpStats(
    void
    )
///
/// @brief Dump PT filtering statistics.
///
{
    DWORD total, monitored, inpt, relevant;

    total = monitored = inpt = relevant = 0;

    if (!gPtMonitored)
    {
        return;
    }

    // Search for the matching instruction.
    for (LIST_ENTRY *list = gPtiCandidatesList.Flink; list != &gPtiCandidatesList; )
    {
        PPTI_CANDIDATE pPtc = CONTAINING_RECORD(list, PTI_CANDIDATE, Link);
        CHAR text[ND_MIN_BUF_SIZE];

        list = list->Flink;

        total++;

        if (pPtc->Monitored)
        {
            monitored++;
        }

        NdToText(&pPtc->Instruction, pPtc->Gla, ND_MIN_BUF_SIZE, text);

        LOG("%04d ---- RIP 0x%016llx, instruction %s\n", total, pPtc->Gla, text);
    }

    LOG("We have %d total instructions modified, %d remaining to inspect, %d in page-tables, %d relevant\n",
        total, monitored, inpt, relevant);
}


static INTSTATUS
IntPtiHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief This callback handles writes that take place inside the in-guest PT filter. All attempts will be blocked.
///
/// @param[in]  Context     The context. Unused.
/// @param[in]  Hook        Hook handle. Unused.
/// @param[in]  Address     The written address. Unused.
/// @param[out] Action      Action. Will be set to #introGuestNotAllowed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    LOG("[PTCORE] Write took place inside the PT agent at GLA %llx, from RIP %llx!\n",
        gVcpu->Gla,
        gVcpu->Regs.Rip);

    IntEnterDebugger();

    *Action = introGuestNotAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiHandleExecute(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief This callback handles instruction fetches that take place inside the in-guest PT filter. All attempts will
/// be blocked.
///
/// @param[in]  Context     The context. Unused.
/// @param[in]  Hook        Hook handle. Unused.
/// @param[in]  Address     The written address. Unused.
/// @param[out] Action      Action. Will be set to #introGuestNotAllowed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    LOG("[PTCORE] Exec took place inside the PT agent at GLA %llx, from RIP %llx!\n",
        gVcpu->Gla,
        gVcpu->Regs.Rip);

    IntEnterDebugger();

    *Action = introGuestNotAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiHookPtDriver(
    void
    )
///
/// @brief Protect the in-guest PT filter against unauthorized access.
///
/// This function will protect the in-guest pt filter against attacks: non-writable sections will be
/// marked non-writable inside the EPT, while non-executable sections will be marked non-executable.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    DWORD i;
    PIMAGE_SECTION_HEADER pSec;
    DWORD sectionRva = 0;
    DWORD sectionCount = 0;

    if (NULL == gPtDriverImage)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntPeListSectionsHeaders(0, gPtDriverImage, gPtDriverSize, &sectionRva, &sectionCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeIterateSections failed with status: 0x%08x\n", status);
        return status;
    }

    pSec = (IMAGE_SECTION_HEADER *)(gPtDriverImage + sectionRva);
    for (i = 0; i < sectionCount; i++, pSec++)
    {
        TRACE("[PTCORE] Hooking section %d (%s) with characteristics 0x%08x against writes\n",
              i, pSec->Name, pSec->Characteristics);

        if (0 == (pSec->Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            status = IntHookObjectHookRegion(gPtDriverHook,
                                             gGuest.Mm.SystemCr3,
                                             pSec->VirtualAddress + gPtDriverAddress,
                                             ROUND_UP((QWORD)pSec->Misc.VirtualSize, PAGE_SIZE),
                                             IG_EPT_HOOK_WRITE,
                                             IntPtiHandleWrite,
                                             NULL, 0, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            }
        }

        if (0 == (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            TRACE("[PTCORE] Hooking section %d (%s) with characteristics 0x%08x against execute\n",
                  i, pSec->Name, pSec->Characteristics);

            status = IntHookObjectHookRegion(gPtDriverHook,
                                             gGuest.Mm.SystemCr3,
                                             pSec->VirtualAddress + gPtDriverAddress,
                                             ROUND_UP((QWORD)pSec->Misc.VirtualSize, PAGE_SIZE),
                                             IG_EPT_HOOK_EXECUTE,
                                             IntPtiHandleExecute,
                                             NULL, 0, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiEnableFiltering(
    void
    )
///
/// @brief Enable PT candidate instruction monitoring.
///
/// This function will start monitoring all the candidate PT instructions inside the .text section of the NT image.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    IntPauseVcpus();

    // Modify all the candidate instructions.
    status = IntPtiMonitorAllPtWriteCandidates();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPtiMonitorAllPtWriteCandidates failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Inside the GPA hook system, remove the EPT hook on all page-tables and make sure we don't place any new ones.
    status = IntHookGpaEnablePtCache();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaEnablePtCache failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[PTCORE] PT filtering enabled!\n");

    gGuest.PtFilterEnabled = TRUE;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        IntHookGpaDisablePtCache();

        IntPtiRestoreAllPtWriteCandidates();
    }

    IntResumeVcpus();

    return status;
}


static INTSTATUS
IntPtiDisableFiltering(
    void
    )
///
/// @brief Disable PT candidate instructions monitoring.
///
/// This function will disable the filtering by:
/// 1. Restoring all candidate instructions;
/// 2. Disabling the PT cache;
/// 3. Removing all mem-table entries.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    IntPauseVcpus();

    // Restore all the candidate instructions.
    status = IntPtiRestoreAllPtWriteCandidates();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPtiRestoreAllPtWriteCandidates failed: 0x%08x\n", status);
    }

    // Re-enable EPT hook on the page tables.
    status = IntHookGpaDisablePtCache();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaDisablePtCache failed: 0x%08x\n", status);
    }

    // Remove mem-tables entries that were allocated inside the agent.
    status = IntMtblRemoveAgentEntries();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMtblRemoveAgentEntries failed: 0x%08x\n", status);
    }

    LOG("[PTCORE] PT filtering disabled!\n");

    gGuest.PtFilterEnabled = FALSE;

    IntResumeVcpus();

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiDeployLoader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called on initial loader deployment.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  AgentTag            Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(GuestVirtualAddress);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(Context);

    LOG("[PTCORE] PT filter loader deployed!\n");

    return INT_STATUS_SUCCESS;
}


static QWORD
IntPtiDeliverDriverForLoad(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD MaxSize,
    _In_opt_ void *Context
    )
///
/// @brief Called by the driver loader, in order to initialize the in-guest PT-filter.
///
/// This function is called by the boot driver agent, and it signals that the PT filter initialization can begin.
/// This function does the following:
/// 1. Writes the PT filter inside the guest space.
/// 2. Initialize the cache, mem-tables and the handlers tables; their uses are the following:
///     - cache - contains guest-physical pages (page-tables) which are not monitored; of an entry is found by
///       the PT filter inside this cache, it will ignore the write, and it will not trigger an exit;
///     - mem-tables - a section dedicated for relocating mem-tables; as this technique places lots of read EPT
///       hooks on the NT image (the instrumented instructions), a high number of switch-case statements will
///       trigger read EPT violations; since the NT slack space is a limited resource, once the PT filter is
///       injected, these switch-case instructions will be relocated inside the PT filter;
///     - handlers - a section which contains the handlers for each instrumented instruction.
///     - check function - this is the main function which checks if an address looks like a page-table or not;
/// 3. Patch relevant info inside the PT filter:
///     - Self map index inside PML4;
///     - Page-table monitored bits - we will exit iff one of these bits is modified;
///     - Relevant offsets inside kernel structures.
/// 4. Protect the PT filter against attacks
///     - write-hook non-writable sections
///     - execute-hook non-executable sections
/// 5. Hook the VE handler - place a hook which will divert execution to the PT filter main handler.
///
/// @param[in]  GuestVirtualAddress The guest address where the PT filter is deployed.
/// @param[in]  MaxSize             Unused.
/// @param[in]  Context             Unused.
///
/// @retval 0 On success; used internally by the agents.
///
{
    INTSTATUS status;
    IMAGE_SECTION_HEADER sec;
    QWORD res;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MaxSize);

    res = 1;

    gPtDriverImage = HpAllocWithTag(gPtDriverSize, IC_TAG_PTI_DRV);
    if (NULL == gPtDriverImage)
    {
        return res;
    }

    gPtDriverAddress = GuestVirtualAddress;

    LOG("[PTCORE] Delivering the PT filter at GVA %llx, size 0x%x...\n", gPtDriverAddress, gPtDriverSize);

    IntPauseVcpus();

    // Load the image.
    status = IntLdrLoadPEImage(gPtDriverx64, sizeof(gPtDriverx64), gPtDriverAddress, gPtDriverImage, gPtDriverSize,
                               LDR_FLAG_FIX_RELOCATIONS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrLoadPEImage failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Deploy the PT driver inside the guest.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, gPtDriverAddress, gPtDriverSize, gPtDriverImage, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Get the cache & table sections.
    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".cache", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .cache section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverCacheAddress = gPtDriverAddress + sec.VirtualAddress;

    TRACE("[PTCORE] Cache at 0x%016llx...\n", gPtDriverCacheAddress);


    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".table", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .table section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverTableAddress = gPtDriverAddress + sec.VirtualAddress;

    TRACE("[PTCORE] Table at 0x%016llx...\n", gPtDriverTableAddress);


    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".handler", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .handler section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverHandlersAddress = gPtDriverAddress + sec.VirtualAddress;
    gPtHandlersTotalSize = sec.Misc.VirtualSize;

    TRACE("[PTCORE] Handlers at 0x%016llx...\n", gPtDriverHandlersAddress);


    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".main", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .main section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverMainAddress = gPtDriverAddress + sec.VirtualAddress;

    TRACE("[PTCORE] Main at 0x%016llx...\n", gPtDriverMainAddress);


    // Fixup all the variables.
    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".rdata", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .main section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverRdataAddress = gPtDriverAddress + sec.VirtualAddress;

    TRACE("[PTCORE] .rdata at 0x%016llx...\n", gPtDriverRdataAddress);


    // Mem-tables area.
    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".memtbl", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .memtbl section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverMemtableAddress = gPtDriverAddress + sec.VirtualAddress;
    gPtMemtableTotalSize = sec.Misc.VirtualSize;

    TRACE("[PTCORE] .memtbl at 0x%016llx...\n", gPtDriverMemtableAddress);


    // GLA check function.
    status = IntPeGetSectionHeaderByName(gPtDriverAddress, NULL, ".lock", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] .lock section not found: 0x%08x!\n", status);
        goto cleanup_and_exit;
    }

    gPtDriverCheckFunction = gPtDriverAddress + sec.VirtualAddress;

    TRACE("[PTCORE] .lock at 0x%016llx...\n", gPtDriverCheckFunction);


    // No need to use IntVirtMemSafeWrite here, as it was already used to deploy the agent, so if that worked,
    // these will work too.

    // Store the self-map index.
    IntKernVirtMemPatchDword(gPtDriverRdataAddress + 0, gGuest.Mm.SelfMapIndex);
    // Store the relevant bits.
    IntKernVirtMemPatchQword(gPtDriverRdataAddress + 8, HOOK_PTS_MONITORED_BITS);
    // Store the attached process offset in KTHREAD.
    IntKernVirtMemPatchQword(gPtDriverRdataAddress + 16, WIN_KM_FIELD(Thread, AttachedProcess));
    // Store the process offset in KTHREAD.
    IntKernVirtMemPatchQword(gPtDriverRdataAddress + 20, WIN_KM_FIELD(Thread, Process));
    // Store the spare offset in EPROCESS.
    IntKernVirtMemPatchQword(gPtDriverRdataAddress + 24, WIN_KM_FIELD(Process, Spare));


    // Create a hook object for the PT filtering driver.
    status = IntHookObjectCreate(0, gGuest.Mm.SystemCr3, &gPtDriverHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Hook the ptfilter driver inside the guest - for now, we only hook the non-writable sections, as during the
    // initialization, the ptfilter driver will write those sections.
    status = IntPtiHookPtDriver();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPtiHookPtDriver failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Hook the ptfilter handler and make it point inside our driver.
    status = IntWinApiHookVeHandler(gPtDriverAddress + gPtDriverEntryPoint, &gPtDriverCloak, NULL, NULL, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeHookVirtualizationExceptionHandler failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    gPtEnableMonitor = TRUE;

    res = 0;

cleanup_and_exit:
    IntResumeVcpus();

    return res;
}


static INTSTATUS
IntPtiCompleteLoader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD ErrorCode,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called once the PT loader finished execution.
///
/// Depending on the injection result, this function will either reset the PT filter state, if injection failed, or it
/// will enable PT filtering, if it succeeded.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  ErrorCode           Injection error code. 0 for success.
/// @param[in]  AgentTag            Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    if (ErrorCode != 0)
    {
        ERROR("[ERROR] PT filter injection failed with error 0x%08x, will bail out.\n", ErrorCode);
        IntPtiResetState();
    }
    else
    {
        gPtPendingInject = FALSE;
        gPtDeployed = TRUE;

        if (gPtEnableMonitor)
        {
            INTSTATUS status = IntPtiEnableFiltering();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPtiEnableFiltering failed: 0x%08x\n", status);
            }
            else
            {
                LOG("[PTCORE] PT filter loaded successfully!\n");
            }
        }
        else
        {
            if (!gGuest.UninitPrepared)
            {
                ERROR("[ERROR] PT filter deliver failed, cannot enable monitoring!\n");
            }
            else
            {
                WARNING("[WARNING] PT filter deliver failed, cannot enable monitoring!\n");
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiDeployUnloader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called as soon as the PT filter unloader has been successfully injected. Disables the PT filtering.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  AgentTag            Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(GuestVirtualAddress);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(Context);

    IntPtiDisableFiltering();

    LOG("[PTCORE] PT filter unloader deployed!\n");

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPtiUnhookPtFilter(
    void
    )
///
/// @brief Remove protection from the PT filter.
///
/// This function will remove the protection from the PT filter (write and execute protection). It will also
/// remove the cloak handle established on the INT 20 handler, and it will free the PT driver image inside
/// Introcore space.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    // Restore the int 20 hook.
    if (NULL != gPtDriverCloak)
    {
        status = IntMemClkUncloakRegion(gPtDriverCloak, MEMCLOAK_OPT_APPLY_PATCH);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
        }

        gPtDriverCloak = NULL;
    }

    // Remove the PT driver agent hooks.
    if (NULL != gPtDriverHook)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gPtDriverHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
        }
    }

    if (NULL != gPtDriverImage)
    {
        HpFreeAndNullWithTag(&gPtDriverImage, IC_TAG_PTI_DRV);
    }

    return status;
}


static QWORD
IntPtiDeliverDriverForUnload(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD MaxSize,
    _In_opt_ void *Context
    )
///
/// @brief This function is called when the boot driver is ready to unload & free the PT filter.
///
/// This function is called when the boot driver has been successfully injected, and now it asks Introcore
/// to actually remove the PT filter. This function will call the thread-safeness, in order to make sure
/// to pointers still point inside the PT filter. If we still have pointers, this function will return 1,
/// and the in-guest boot driver will spin for a while before trying again. If everything is OK and all
/// pointers have left the PT filter, it will return 0, and the PT filter will be permanently freed inside
/// the guest by the boot driver.
///
/// @param[in]  GuestVirtualAddress     Unused.
/// @param[in]  MaxSize                 Unused.
/// @param[in]  Context                 Unused.
///
/// @retval 0 If the PT filter can safely be freed inside the guest.
/// @retval 1 If the PT filter cannot be safely freed inside the guest.
///
{
    INTSTATUS status;
    BOOLEAN postpone = FALSE;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MaxSize);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    // Make sure there are no RIPs inside the agent.
    IntPauseVcpus();

    status = IntThrSafeCheckThreads(THS_CHECK_ONLY | THS_CHECK_PTFILTER);
    if (INT_STATUS_CANNOT_UNLOAD == status)
    {
        LOG("[WARNING] Cannot unload yet, RIPs still point inside the filter!\n");
        postpone = TRUE;
    }

    IntResumeVcpus();

    if (postpone)
    {
        return 1;
    }

    status = IntPtiUnhookPtFilter();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPtiUnhookPtFilter failed: 0x%08x\n", status);
    }
    else
    {
        LOG("[PTCORE] PT filter unhooked successfully!\n");
    }

    return 0;
}


static INTSTATUS
IntPtCompleteUnloader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD ErrorCode,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called once the agent unloader has finished executing.
///
/// This function will reset the PT state and it will disable the power-state spin wait, if it was enabled. Check
/// out winpower.c for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(ErrorCode);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    IntPtiResetState();

    LOG("[PTCORE] PT filter unloaded successfully!\n");

    status = IntWinPowDisableSpinWait();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinPowDisableSpinWait failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPtiInjectPtFilter(
    void
    )
///
/// @brief Inject the PT filter inside the guest.
///
/// This function will initiate the PT filter injection.
/// NOTE: If this function return success, it does not necessarily means that the PT filter has been successfully
/// injected, it just means that it has been successfully scheduled for injection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If Introcore is preparing to unload.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the OS is not 64 bit Windows RS4 or newer.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If the PT filter ha been already injected.
///
{
    INTSTATUS status;

    if (gGuest.UninitPrepared)
    {
        ERROR("[ERROR] Uninit in progress, cannot deploy the PT filtering agent now!\n");
        return INT_STATUS_NOT_INITIALIZED;
    }

    // Normally, we support filtering any x64 Windows. However, we intend to use it only on RS4 and newer.
    if (gGuest.OSType != introGuestWindows || !gGuest.Guest64 || gGuest.OSVersion < 17134)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // If the agent has already been deployed, bail out.
    if (gPtDeployed || gPtPendingInject || gPtPendingRemove)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    // Get the ptfilter driver info.
    status = IntLdrGetImageSizeAndEntryPoint(gPtDriverx64, sizeof(gPtDriverx64), &gPtDriverSize, &gPtDriverEntryPoint);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrGetImageSizeAndEntryPoint failed: 0x%08x\n", status);
        return status;
    }

    gPtPendingInject = TRUE;

    status = IntWinAgentInject(IntPtiDeployLoader, IntPtiCompleteLoader, IntPtiDeliverDriverForLoad,
                               NULL, gPtDriverx64, gPtDriverSize, TRUE, IG_AGENT_TAG_PT_DRIVER, AGENT_TYPE_PT_LOADER,
                               NULL, 0, NULL, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentInject failed: 0x%08x\n", status);
        gPtPendingInject = FALSE;
    }

    return status;
}


INTSTATUS
IntPtiRemovePtFilter(
    _In_ DWORD AgOpts
    )
///
/// @brief Removes the PT filter.
///
/// This function will initiate the PT filter unloading procedure. Once this is done, all monitored instructions will
/// be reverted to their original values.
/// NOTE: If this function return success, it does not necessarily means that the PT filter has been successfully
/// removed, it just means that it has been successfully scheduled for removal.
///
/// @param[in]  AgOpts  Agent options, passed to the #IntWinAgentInject function.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the PT filter was not previously injected inside the guest.
///
{
    INTSTATUS status;

    // Agent not deployed - nothing to do here.
    if (!(gPtDeployed || gPtPendingInject) || gPtPendingRemove)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gGuest.BugCheckInProgress)
    {
        status = IntPtiDisableFiltering();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPtiDisableFiltering failed: 0x%08x\n", status);
        }

        status = IntPtiUnhookPtFilter();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPtiUnhookPtFilter failed: 0x%08x\n", status);
        }

        // Overwrite the whole driver with zeros.
        // This SHOULD be safe. We will only get here if `BugCheckInProgress` is set.
        // `BugCheckInProgress` will only be set if the guest reaches our hook inside
        // `KiDisplayBlueScreen` and by that time we *assume* that there's only one
        // VCPU running (with the rip inside our hook). Thus, there *shouldn't* be any
        // other VCPUs inside the PT Filter.
        for (DWORD page = 0; page < gPtDriverSize; page += PAGE_SIZE)
        {
            PBYTE pMap;

            status = IntVirtMemMap(gPtDriverAddress + page, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pMap);
            if (!INT_SUCCESS(status))
            {
                continue;
            }

            memzero(pMap, PAGE_SIZE);

            IntVirtMemUnmap(&pMap);
        }

        IntPtiResetState();

        LOG("[PTCORE] PT filter unhooked successfully!\n");

        return status;
    }

    gPtPendingRemove = TRUE;

    return IntWinAgentInject(IntPtiDeployUnloader, IntPtCompleteUnloader, IntPtiDeliverDriverForUnload,
                             NULL, gPtDriverx64, sizeof(gPtDriverx64), TRUE,
                             IG_AGENT_TAG_PT_DRIVER, AGENT_TYPE_PT_UNLOADER,
                             NULL, AgOpts, NULL, 0, NULL);
}


BOOLEAN
IntPtiIsPtrInAgent(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    )
///
/// @brief Check if an address points inside the PT filter. Ignore non-executable sections when doing so.
///
/// @param[in]  Ptr     The pointer.
/// @param[in]  Type    Live RIP or stack value.
///
/// @retval True if Ptr points inside the PT filter, false otherwise.
///
{
    if (!gPtDeployed || (0 == gPtDriverAddress))
    {
        return FALSE;
    }
    else
    {
        if (ptrLiveRip == Type)
        {
            return Ptr >= gPtDriverAddress && Ptr < gPtDriverAddress + gPtDriverSize;
        }
        // >, because the base of our agent may still be on some stacks due to the allocation.
        else if (Ptr > gPtDriverAddress && Ptr < gPtDriverAddress + gPtDriverSize)
        {
            IMAGE_SECTION_HEADER sec = { 0 };
            INTSTATUS status;

            status = IntPeGetSectionHeaderByRva(gPtDriverAddress, NULL, (DWORD)(Ptr - gPtDriverAddress), &sec);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPeGetSectionHeaderByRva failed for address %llx, agent at 0x%016llx, size %d\n",
                      Ptr, gPtDriverAddress, gPtDriverSize);
                return FALSE;
            }

            // If the detected pointer is inside an executable section, we will bail out. Otherwise, simply ignore
            // pointers which don't lead to code, as they are most likely stray pointers.
            return (!!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE));
        }
        else
        {
            return FALSE;
        }
    }
}


INTSTATUS
IntPtiCacheRemove(
    _In_ QWORD Gpa
    )
///
/// @brief Remove a guest physical page from the PT filter cache.
///
/// This function removes a guest physical page from the PT filter cache. Removing an entry is required, for example,
/// when hooking it for the first time.
///
/// @param[in]  Gpa The guest physical address to be removed from the PT filter cache. Low 12 bits are ignored.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the PT filter is not initialized.
///
{
    INTSTATUS status;
    QWORD cacheIndex = Gpa & 0x1FF000;
    QWORD cacheGva = gPtDriverCacheAddress + cacheIndex;
    PQWORD pEntries = NULL;

    if (0 == gPtDriverCacheAddress || 0 == cacheGva || 0 == gPtDriverAddress)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Gpa &= PHYS_PAGE_MASK;

    status = IntVirtMemMap(cacheGva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pEntries);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", cacheGva, status);
        return status;
    }

    for (DWORD i = 0; i < 512; i++)
    {
        if (pEntries[i] == Gpa)
        {
            pEntries[i] = 0;
        }
    }

    IntVirtMemUnmap(&pEntries);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPtiCacheAdd(
    _In_ QWORD Gpa
    )
///
/// @brief Add a guest-physical address to the PT filter cache of entries for which an exit is not required.
///
/// This function updates the PT filter cache by adding the designated value to it. The cache is used by the PT
/// filter to know which guest-physical addresses are not hooked, and, therefore, it needs not to generate
/// a VM exit.
///
/// @param[in]  Gpa     The guest physical address to be added to the cache. Low 12 bits are ignored.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the PT filter is not initialized.
///
{
    INTSTATUS status;
    DWORD i;
    QWORD cacheIndex = Gpa & 0x1FF000;
    QWORD cacheGva = gPtDriverCacheAddress + cacheIndex;
    PQWORD pEntries = NULL;

    if (0 == gPtDriverCacheAddress || 0 == cacheGva || 0 == gPtDriverAddress)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Gpa &= PHYS_PAGE_MASK;

    status = IntVirtMemMap(cacheGva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pEntries);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", cacheGva, status);
        return status;
    }

    for (i = 0; i < 512; i++)
    {
        if (pEntries[i] == Gpa)
        {
            break;
        }

        if (pEntries[i] == 0)
        {
            pEntries[i] = Gpa;
            break;
        }
    }

    if (i == 512)
    {
        pEntries[__rdtsc() % 512] = Gpa;
    }

    IntVirtMemUnmap(&pEntries);

    return INT_STATUS_SUCCESS;
}


QWORD
IntPtiGetAgentAddress(
    void
    )
///
/// @brief Get the guest virtual address where the PT filter resides.
///
/// @retval The guest virtual address where the PT filter resides.
///
{
    return gPtDriverAddress;
}


QWORD
IntPtiAllocMemtableSpace(
    _In_ QWORD Rip,
    _In_ DWORD Size
    )
///
/// @brief Allocate space for a mem-table.
///
/// Instrumenting so many instructions has a great disadvantage: there are high chances that we will hit pages
/// that contain switch-case clauses. Since we monitor all pages that are modified by Introcore against reads,
/// this will lead to a very high number of mem-tables that must be relocated. Since the slack space size is
/// quite small, we cannot relocate all these instructions inside this slack space; instead, we make use of the
/// PT filter itself - we reserved a large section specially for these mem-tables, which will be relocated inside
/// the PT filter space, instead of the NT slack space.
///
/// @param[in]  Rip     Rip of the instruction to be relocated using mem-tables.
/// @param[in]  Size    Size required.
///
/// @retval A guest virtual address pointing inside a section of the PT filter, which can be used by mem-tables.
///
{
    INTSTATUS status;
    QWORD ptr;
    QWORD idx;

    if (!gPtDeployed || gPtDriverMemtableAddress == 0 || gPtPendingRemove)
    {
        return 0;
    }

    if (Size + gPtMemtableSize > gPtMemtableTotalSize)
    {
        ERROR("[ERROR] Could not allocate space in agent: requested %d bytes, used %d bytes, total %d bytes\n",
              Size, gPtMemtableSize, gPtMemtableTotalSize);
        return 0;
    }

    ptr = gPtDriverMemtableAddress + gPtMemtableSize;

    idx = gPtTableIndexes[Rip & TABLE_BUCKET_MASK];
    if (idx >= MAX_ENTRIES_PER_BUCKET)
    {
        ERROR("[ERROR] Maximum table index reached for bucket %lld!\n", Rip & TABLE_BUCKET_MASK);
        IntEnterDebugger();
        return 0;
    }

    // Store the handler RIP.
    status = IntKernVirtMemWrite(gPtDriverTableAddress + ((Rip & TABLE_BUCKET_MASK) << 12) + idx * 16,
                                 sizeof(Rip), &Rip);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        IntEnterDebugger();
        return 0;
    }

    status = IntKernVirtMemWrite(gPtDriverTableAddress + ((Rip & TABLE_BUCKET_MASK) << 12) + idx * 16 + 8,
                                 sizeof(ptr), &ptr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        IntEnterDebugger();
        return 0;
    }

    TRACE("[PTFILTER] Allocated memtable space for RIP 0x%016llx at 0x%016llx, size %d bytes\n", Rip, ptr, Size);

    gPtTableIndexes[Rip & TABLE_BUCKET_MASK]++;

    gPtMemtableSize += Size;

    return ptr;
}


void
IntPtiHandleGuestResumeFromSleep(
    void
    )
///
/// @brief Sets PtFilterWaiting to true if PT filtering was enabled, or to false otherwise.
///
{
    gGuest.PtFilterWaiting = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER);
}
