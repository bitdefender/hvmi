/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "swapgs.h"
#include "guests.h"
#include "icache.h"
#include "memcloak.h"
#include "slack.h"
#include "winpe.h"

///
/// @file swapgs.c
///
/// @brief This file contains a workaround for the CVE-2019-1125 vulnerability.
///
/// Since we have discovered the SWAPGS attack (CVE-2019-1125), we were able to provide a workaround, directly inside
/// the introspection engine, in order to mitigate the vulnerability. The way this works is by simply serializing
/// all the SWAPGS gadgets that are vulnerable. Note that we focus mainly on SWAPGS variant 2, which is the more
/// dangerous form - executing the SWAPGS instruction even if it shouldn't.
///
/// IMPORTANT 1: All SWAPGS instructions lie in .text or KVASCODE sections, which are non-paged!
/// IMPORTANT 2: All gadgets are followed by GS based addressing, which simplified hooking!
/// IMPORTANT 3: Gadgets which are located inside the KVASCODE section must be relocated inside the same section.
///              The reason is that under KPTI, only KVASCODE section is mapped in user-mode, and the CR3 switch
///              takes place in that section. If we place the handler in the .text section, the handler would execute
///              before switching the CR3, and it would cause a triple-fault in guest.
///


///
/// Describes one SWAPGS handler. A SWAPGS handler may be shared by multiple SWAPGS gadgets.
///
typedef struct _SWAPGS_HANDLER
{
    LIST_ENTRY          Link;               ///< List entry element.
    QWORD               Slack;              ///< Slack address where the handler has been allocated.
    QWORD               Section;            ///< NT section of the handler.
    BYTE                Instruction[16];    ///< The instruction that has been replaced by a jump.
    BYTE                InstructionLength;  ///< Length of the replaced instruction.
    BYTE                Handler[32];        ///< Handler code.
    BYTE                HandlerLength;      ///< Handler code length.
    void               *Cloak;              ///< Cloak handle to the handler.
} SWAPGS_HANDLER;

///
/// Describes one intercepted gadget. Unlike the template, this describes each intercepted vulnerable code sequence.
/// Multiple such gadgets may be handled by a single SWAPGS_HANDLER.
///
typedef struct _SWAPGS_GADGET
{
    LIST_ENTRY          Link;       ///< List entry element.
    QWORD               Gla;        ///< Linear address of the instrumented SWAPGS gadget.
    BYTE                Length;     ///< Length of the instrumented SWAPS gadget.
    void               *Cloak;      ///< Cloak handle.
    SWAPGS_HANDLER      *Handler;   ///< SWAPGS handler.
} SWAPGS_GADGET;

/// List of all the hooked gadgets.
LIST_HEAD gGadgets = LIST_HEAD_INIT(gGadgets);

/// List of all distinct handlers.
LIST_HEAD gHandlers = LIST_HEAD_INIT(gHandlers);

/// TRUE if we mitigated the SWAPGS issue.
BOOLEAN gMitigated;


static SWAPGS_HANDLER *
IntSwapgsInstallHandler(
    _In_ QWORD Section,
    _In_ BYTE Instruction[16],
    _In_ BYTE Length
    )
///
/// @brief Install a handler for a given instruction.
///
/// This function searched for a handler for the specified instruction (which follows SWAPGS). If one is found, it will
/// be installed as a mitigation handler for the identified gadget. Otherwise, a new handler will be allocated.
/// The handler is very simple:
///         LFENCE
///         Instruction
///         PUSHFQ
///         ADD [rsp + 8], Length
///         POPFQ
///         RETN
///
/// @param[in]  Section     The section inside NT of the required handler (.text or KVASCODE)
/// @param[in]  Instruction Instruction bytes of the instruction following the SWAPGS (must be GS based addressing).
/// @param[in]  Length      Length of the identified instruction.
///
/// @retval The handler installed for this instruction.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    // First, search for an already-installed handler.
    list = gHandlers.Flink;
    while (list != &gHandlers)
    {
        SWAPGS_HANDLER *hnd = CONTAINING_RECORD(list, SWAPGS_HANDLER, Link);

        list = list->Flink;

        if ((hnd->Section == Section) && (hnd->InstructionLength == Length) &&
            (0 == memcmp(Instruction, hnd->Instruction, Length)))
        {
            return hnd;
        }
    }

    // No match found, allocate a fresh handler.
    SWAPGS_HANDLER *hnd = HpAllocWithTag(sizeof(*hnd), IC_TAG_SGDH);
    if (NULL == hnd)
    {
        ERROR("[ERROR] HpAllocWithTag failed!\n");
        return 0;
    }

    InsertTailList(&gHandlers, &hnd->Link);

    hnd->Section = Section;
    hnd->InstructionLength = Length;
    memcpy(hnd->Instruction, Instruction, Length);

    // Store the LFENCE.
    hnd->Handler[hnd->HandlerLength++] = 0x0F;
    hnd->Handler[hnd->HandlerLength++] = 0xAE;
    hnd->Handler[hnd->HandlerLength++] = 0xE8;

    // Store the original instruction.
    memcpy(hnd->Handler + hnd->HandlerLength, Instruction, Length);

    hnd->HandlerLength += Length;

    // Store a PUSHFQ.
    hnd->Handler[hnd->HandlerLength++] = 0x9C;

    // Store an "ADD [rsp + 8], x", in order to RET exactly after the modified instruction.
    hnd->Handler[hnd->HandlerLength++] = 0x48;
    hnd->Handler[hnd->HandlerLength++] = 0x83;
    hnd->Handler[hnd->HandlerLength++] = 0x44;
    hnd->Handler[hnd->HandlerLength++] = 0x24;
    hnd->Handler[hnd->HandlerLength++] = 0x08;
    hnd->Handler[hnd->HandlerLength++] = Length - 5;

    // Store a POPFQ.
    hnd->Handler[hnd->HandlerLength++] = 0x9D;

    hnd->Handler[hnd->HandlerLength++] = 0xC3;

    // Allocate slack space for the handler.
    status = IntSlackAlloc(gGuest.KernelVa, FALSE, hnd->HandlerLength, &hnd->Slack, Section);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSlackAlloc failed: 0x%08x\n", status);
        return 0;
    }

    // Store the handler & cloak it.
    status = IntMemClkCloakRegion(hnd->Slack, 0, hnd->HandlerLength, MEMCLOAK_OPT_APPLY_PATCH,
                                  NULL, hnd->Handler, NULL, &hnd->Cloak);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
        return 0;
    }

    // All good, return the freshly allocated slack.
    return hnd;
}


///
/// SWAPGS gadget state.
///
typedef enum _SWAPGS_SSTATE
{
    swapgsSstateNone = 0,       ///< No state, just started scanning.
    swapgsSstateJcc,            ///< A conditional jump was found.
    swapgsSstatePush,           ///< A PUSH was found.
    swapgsSstateSwapgs,         ///< The SWAPGS instruction was found.
    swapgsSstateGsBasedAccess   ///< A GS based addressing instruction was found. This is where we start instrumenting.
} SWAPGS_SSTATE;



INTSTATUS
IntSwapgsStartMitigation(
    void
    )
///
/// @brief Scan the kernel for vulnerable SWAPGS gadgets, and mitigate CVE-2019-1125, when such gadgets are found.
///
/// This function scans the NT image (.text and KVASCODE sections) for code sequences that are vulnerable to
/// SWAPGS variant 2. When such a sequence is found, it will replace the first GS based access after the
/// SWAPGS with a JMP to a small handler installed inside the NT slack space, which will simply serialize
/// execution using LFENCE.
/// Example: Considering the sequence:
///         TEST    [mem], imm
///         JZ      skip_swapgs
///         SWAPGS
///skip_swapgs:
///         MOV     r10, gs:[0x188]
///         ...
/// we will replace the "MOV r10, gs:[0x188]" instruction with a "CALL" to a handler installed inside the slack
/// space, which will force a "LFENCE" before actually doing the GS based addressing.
/// NOTE: This scanning & instrumentation is done with the VCPUs paused.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If KPTI is not active, or if the guest is not x64, or if it is not Windows.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If the NT image headers are corrupt.
/// @retval #INT_STATUS_NOT_SUPPORTED If a handler cannot be installed.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    DWORD i, count;
    CHAR secname[9];
    QWORD secid, seqstart, seqoffset;
    SWAPGS_SSTATE state;
    PBYTE pSectionBuffer = NULL;
    IMAGE_DOS_HEADER *pDos;
    IMAGE_FILE_HEADER *pFileHeader;
    DWORD secheadersRva;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SWAPGS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!gGuest.KptiActive)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!gGuest.Guest64)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntPauseVcpus();

    // Parse the kernel and find all the code gadgets that match this template.
    STATS_ENTER(statsSwapgsInsSearch);

    pDos = (IMAGE_DOS_HEADER *)gWinGuest->KernelBuffer;

    pFileHeader = (IMAGE_FILE_HEADER *)(gWinGuest->KernelBuffer + pDos->e_lfanew + 4);

    secheadersRva = pDos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader;

    for (DWORD seci = 0; seci < pFileHeader->NumberOfSections; seci++)
    {
        const IMAGE_SECTION_HEADER *pSec = (const IMAGE_SECTION_HEADER *)(gWinGuest->KernelBuffer + secheadersRva +
                                                                          sizeof(IMAGE_SECTION_HEADER) * seci);

        // Make sure the section is ok.
        if (pSec->VirtualAddress >= gGuest.KernelSize ||
            pSec->Misc.VirtualSize + pSec->VirtualAddress > gGuest.KernelSize)
        {
            ERROR("[ERROR] The section seems to point outside the kernel image!\n");
            status = INT_STATUS_INVALID_INTERNAL_STATE;
            goto cleanup_and_exit;
        }

        // We only parse executable, non-paged, non-discardable sections.
        if (0 == (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            0 == (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) ||
            0 != (pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            continue;
        }

        // Skip all non-.text and non-KVASCODE sections.
        if (0 != memcmp(pSec->Name, ".text", 5) && 0 != memcmp(pSec->Name, "KVASCODE", 8))
        {
            continue;
        }

        count = 0;

        memcpy(secname, pSec->Name, 8);

        if (0 == memcmp(pSec->Name, "KVASCODE", 8))
        {
            // KVASCODE gadgets must be relocated inside the same section, otherwise we may end up branching from
            // this section in another one which isn't mapped due to KPTI.
            memcpy(&secid, pSec->Name, 8);
        }
        else
        {
            // Not KVASCODE, any executable non-paged section will do.
            secid = 0;
        }

        secname[8] = 0;
        i = 0;
        seqstart = 0;
        seqoffset = 0;
        state = swapgsSstateNone;

        TRACE("[SWAPGS] Parsing section '%s', virtual-size 0x%08x...\n", secname, pSec->Misc.VirtualSize);

        pSectionBuffer = gWinGuest->KernelBuffer + pSec->VirtualAddress;

        while (i < pSec->Misc.VirtualSize)
        {
            INSTRUX instrux;
            QWORD offset = i;
            QWORD target = gGuest.KernelVa + pSec->VirtualAddress + offset;
            DWORD reloffs = 0;
            NDSTATUS ndstatus;

            ndstatus = NdDecodeEx(&instrux, pSectionBuffer + offset, pSec->Misc.VirtualSize - i, ND_CODE_64, ND_DATA_64);
            if (!ND_SUCCESS(ndstatus))
            {
                i += 1;
                continue;
            }

            if (instrux.Seg == ND_PREFIX_G2_SEG_GS && state == swapgsSstateSwapgs &&
                !ND_IS_OP_REG(&instrux.Operands[0], ND_REG_GPR, 8, NDR_RSP))
            {
                // We found a GS based addressing after SWAPGS. Make sure it does NOT modify RSP, or else, we won't be
                // able to RET from the handler!
                // Also, if the following instruction is a serializing instruction, this will just reset the entire
                // state, as we won't have to mitigate anything.
                state = swapgsSstateGsBasedAccess;
            }
            else if (instrux.Instruction == ND_INS_SWAPGS && (state == swapgsSstateJcc || state == swapgsSstatePush))
            {
                // We have a SWAPGS after either a conditional branch or some PUSHes.
                state = swapgsSstateSwapgs;
            }
            else if (instrux.Instruction == ND_INS_PUSH && (state == swapgsSstateJcc || state == swapgsSstatePush))
            {
                // PUSH after PUSH or conditional branch.
                state = swapgsSstatePush;
            }
            else if (instrux.Instruction == ND_INS_Jcc && state == swapgsSstateNone)
            {
                // Found the conditional branch!
                seqstart = target;
                seqoffset = offset;
                state = swapgsSstateJcc;
            }
            else
            {
                // Nothing interesting, reset the state machine.
                state = swapgsSstateNone;
            }

            if (swapgsSstateGsBasedAccess == state)
            {
                BYTE call[16] =
                {
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                };

                LOG("[SWAPGS] Found vulnerable sequence at 0x%016llx, offset 0x%llx, context "
                    "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                    seqstart, seqoffset,
                    pSectionBuffer[seqoffset + 0],
                    pSectionBuffer[seqoffset + 1],
                    pSectionBuffer[seqoffset + 2],
                    pSectionBuffer[seqoffset + 3],
                    pSectionBuffer[seqoffset + 4],
                    pSectionBuffer[seqoffset + 5],
                    pSectionBuffer[seqoffset + 6],
                    pSectionBuffer[seqoffset + 7]
                   );

                // Get a handler.
                SWAPGS_HANDLER *handler = IntSwapgsInstallHandler(secid, instrux.InstructionBytes, instrux.Length);
                if (NULL == handler)
                {
                    ERROR("[ERROR] Failed installing a handler!\n");
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }

                // Allocate a new gadget object.
                SWAPGS_GADGET *gadget = HpAllocWithTag(sizeof(*gadget), IC_TAG_SGDG);
                if (NULL == gadget)
                {
                    ERROR("[ERROR] HpAllocWithTag failed!\n");
                    status = INT_STATUS_INSUFFICIENT_RESOURCES;
                    goto cleanup_and_exit;
                }

                InsertTailList(&gGadgets, &gadget->Link);

                // Found a SWAPGS gadget, patch it out!
                gadget->Gla = target;
                gadget->Length = instrux.Length;
                gadget->Handler = handler;

                // Note: the vulnerable sequences are always of the form "Jcc/SWAPGS", which are 5 bytes long.
                reloffs = (DWORD)(handler->Slack - target - 5);

                // Build a "CALL gadget" instruction.
                call[0] = 0xE8;     // CALL opcode
                call[1] = (reloffs >> 0) & 0xFF;
                call[2] = (reloffs >> 8) & 0xFF;
                call[3] = (reloffs >> 16) & 0xFF;
                call[4] = (reloffs >> 24) & 0xFF;

                // Intercept the instruction.
                status = IntMemClkCloakRegion(gadget->Gla, 0, instrux.Length, MEMCLOAK_OPT_APPLY_PATCH,
                                              pSectionBuffer + offset,
                                              call, NULL, &gadget->Cloak);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
                    goto cleanup_and_exit;
                }

                IntIcFlushAddress(gGuest.InstructionCache, gadget->Gla, IC_ANY_VAS);

                count++;
            }

            i += instrux.Length;
        }

        TRACE("[SWAPGS] Patched %d instructions in section '%s'!\n", count, secname);
    }

    status = INT_STATUS_SUCCESS;

    gMitigated = TRUE;

cleanup_and_exit:
    IntResumeVcpus();

    STATS_EXIT(statsSwapgsInsSearch);

    return status;
}


void
IntSwapgsUninit(
    void
    )
///
/// @brief Uninit the SWAPGS mitigation.
///
/// All gadgets will be restored, making the OS vulnerable again.
///
{
    LIST_ENTRY *list;

    list = gGadgets.Flink;
    while (list != &gGadgets)
    {
        SWAPGS_GADGET *gadget = CONTAINING_RECORD(list, SWAPGS_GADGET, Link);

        list = list->Flink;

        // Remove the CALL.
        if (NULL != gadget->Cloak)
        {
            IntMemClkUncloakRegion(gadget->Cloak, MEMCLOAK_OPT_APPLY_PATCH);

            gadget->Cloak = NULL;
        }

        RemoveEntryList(&gadget->Link);

        HpFreeAndNullWithTag(&gadget, IC_TAG_SGDG);
    }

    list = gHandlers.Flink;
    while (list != &gHandlers)
    {
        SWAPGS_HANDLER *handler = CONTAINING_RECORD(list, SWAPGS_HANDLER, Link);

        list = list->Flink;

        if (NULL != handler->Cloak)
        {
            IntMemClkUncloakRegion(handler->Cloak, MEMCLOAK_OPT_APPLY_PATCH);

            handler->Cloak = NULL;
        }

        RemoveEntryList(&handler->Link);

        HpFreeAndNullWithTag(&handler, IC_TAG_SGDH);
    }

    gMitigated = FALSE;
}


void
IntSwapgsDisable(
    void
    )
///
/// @brief Disable SWAPGS mitigations. Must be used only for PrepareUninit.
///
{
    LIST_ENTRY *list;

    list = gGadgets.Flink;
    while (list != &gGadgets)
    {
        SWAPGS_GADGET *gadget = CONTAINING_RECORD(list, SWAPGS_GADGET, Link);

        list = list->Flink;

        if (NULL != gadget->Cloak)
        {
            IntMemClkUncloakRegion(gadget->Cloak, MEMCLOAK_OPT_APPLY_PATCH);

            gadget->Cloak = NULL;

            // Flush the icache entry.
            IntIcFlushAddress(gGuest.InstructionCache, gadget->Gla, IC_ANY_VAS);
        }
    }
}


BOOLEAN
IntSwapgsIsPtrInHandler(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ QWORD *Gadget
    )
///
/// @brief Check if a pointer points inside a SWAPGS handler.
///
/// @param[in]  Ptr     The pointer to be checked.
/// @param[in]  Type    Live RIP or stack value.
/// @param[out] Gadget  The gadget address, if any is found, or NULL otherwise.
///
/// @retval True if the Ptr points inside a gadget, false otherwise.
///
{
    LIST_ENTRY *list;

    list = gHandlers.Flink;
    while (list != &gHandlers)
    {
        SWAPGS_HANDLER *handler = CONTAINING_RECORD(list, SWAPGS_HANDLER, Link);

        list = list->Flink;

        if (Ptr >= handler->Slack && Ptr < handler->Slack + handler->HandlerLength)
        {
            WARNING("[WARNING] Found %s ptr 0x%016llx in SWAPGS handler: slack addr 0x%016llx, size %x\n",
                    Type == ptrLiveRip ? "live RIP" : "stack value", Ptr, handler->Slack, handler->HandlerLength);

            if (NULL != Gadget)
            {
                *Gadget = handler->Slack;
            }

            return TRUE;
        }
    }

    if (NULL != Gadget)
    {
        *Gadget = 0;
    }

    return FALSE;
}


QWORD
IntSwapgsRelocatePtrIfNeeded(
    _In_ QWORD Ptr
    )
///
/// @brief Relocate a pointer if it points inside a SWAPGS gadget, and make it point inside the installed handler.
///
/// @param[in]  Ptr     The pointer to be checked.
///
/// @retval The new value for the pointer, if it was relocated.
///
{
    LIST_ENTRY *list;

    list = gGadgets.Flink;
    while (list != &gGadgets)
    {
        SWAPGS_GADGET *gadget = CONTAINING_RECORD(list, SWAPGS_GADGET, Link);
        list = list->Flink;

        // We can check past the beginning.
        if (Ptr > gadget->Gla && Ptr < gadget->Gla + gadget->Length)
        {
            return gadget->Handler->Slack + (Ptr - gadget->Gla);
        }
    }

    // No modification, return it as it is.
    return Ptr;
}
