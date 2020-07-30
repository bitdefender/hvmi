/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook_ptwh.h"
#include "decoder.h"
#include "gpacache.h"
#include "hook.h"


INTSTATUS
IntHookPtwEmulateWrite(
    _In_ QWORD Address
    )
///
/// @brief Emulate a write that took place on page table entry at Address.
///
/// This function will call the page table write emulator on the indicated physical address. This function will
/// be called, usually, from the EPT write handler, whenever detecting a write on a page-table. This function
/// will also fill the PtEmuBuffer field of the current VCPU with the relevant information: old page-table entry
/// value and new page-table entry value.
///
/// @param[in]  Address Written page-table entry (guest physical address).
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If a page-table write has already been emulated during this exit.
///
{
    INTSTATUS status;
    QWORD entryAddr, entrySize, byteOffs, oldValue, newValue;
    OPERAND_VALUE writtenValue = { 0 };
    DWORD writeSize;
    PIG_ARCH_REGS regs;
    PINSTRUX instrux;

    if (gVcpu->PtEmuBuffer.Valid)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    STATS_ENTER(statsPtWriteEmu);

    entrySize = (gGuest.Guest64 ? 8 : gGuest.PaeEnabled ? 8 : 4);

    entryAddr = Address & ~(entrySize - 1);

    byteOffs = Address & (entrySize - 1);

    instrux = &gVcpu->Instruction;
    regs = &gVcpu->Regs;

    // Accessed size.
    if (instrux->Operands[0].Size > 8)
    {
        ERROR("[ERROR] Unsupported access size: %d at RIP %llx, instruction '%s'!\n",
              instrux->Operands[0].Size, regs->Rip, instrux->Mnemonic);

        status = INT_STATUS_NOT_SUPPORTED;
        goto cleanup_and_exit;
    }

    writeSize = instrux->Operands[0].Size;

    // Check for access that spills in the next entry.
    if (byteOffs + writeSize > entrySize)
    {
        ERROR("[ERROR] Access at %llx spills in the next entry, size %d, instruction '%s'\n",
              Address, writeSize, instrux->Mnemonic);

        status = INT_STATUS_NOT_SUPPORTED;
        goto cleanup_and_exit;
    }

    // Fetch the old PT value.
    status = IntGpaCacheFetchAndAdd(gGuest.GpaCache, entryAddr, (DWORD)entrySize, (PBYTE)&oldValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed at GPA 0x%016llx: 0x%08x\n", entryAddr, status);
        goto cleanup_and_exit;
    }

    // Decode & emulate the PT write at the same time. This is very important:
    // 1. A CMPXCHG instruction may have different behavior when we decode it versus when it will be emulated.
    //    For example, the MiStealPage tries to modify a PTE using a CMPXCHG instruction (with the PTE NOT having
    //    the A bit set). If the A bit is NOT set when we decode it, we will think the exchange will be made.
    //    However, if the A bit will be set later by another CPU, after we handle the write but before the
    //    instruction is emulated, we would end up protecting the wrong page.
    // 2. If a swap out operation takes place and another CPU is emulating a write inside the page that is being
    //    swapped out, we may end up with integrity violations, because we will compute the hash on the old page,
    //    and in the time frame until we emulate the PT write, someone may modify the original page content.
    status = IntDecEmulatePTWrite(&newValue);
    if (!INT_SUCCESS(status))
    {
        // Fallback - use the bigger, slower decoder, which will not emulate the access.
        PBYTE p = (PBYTE)&oldValue + byteOffs;
        INTSTATUS status2;

        ERROR("[ERROR] IntDecEmulatePTWrite failed: 0x%08x\n", status);

        // Check for MOVNTI [rcx], *.
        if (instrux->Instruction == ND_INS_MOVNTI && instrux->Operands[0].Info.Memory.Base == NDR_RCX)
        {
            IntDumpArchRegs(&gVcpu->Regs);

            LOG("Dumping memory pointed by RCX:\n");
            IntDumpGva(gVcpu->Regs.Rcx & PAGE_MASK, 0x1000, gVcpu->Regs.Cr3);

            LOG("Dumping memory pointed by RDX:\n");
            IntDumpGva(gVcpu->Regs.Rdx & PAGE_MASK, 0x1000, gVcpu->Regs.Cr3);

            // Dump the PTS hooks state.
            IntHookPtsDump();
        }

        IntEnterDebugger();

        status2 = IntDecGetWrittenValueFromInstruction(instrux, regs, p, &writtenValue);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntDecEmulatePTWrite failed with 0x%08x, "
                  "IntDecGetWrittenValueFromInstruction failed with 0x%08x\n", status, status2);
            goto cleanup_and_exit;
        }

        newValue = writtenValue.Value.QwordValues[0];
        writeSize = writtenValue.Size;
    }
    else
    {
        gVcpu->PtEmuBuffer.Emulated = TRUE;
    }

    gVcpu->PtEmuBuffer.Valid = TRUE;
    gVcpu->PtEmuBuffer.Partial = entrySize > writeSize;
    gVcpu->PtEmuBuffer.Old = oldValue;
    gVcpu->PtEmuBuffer.New = newValue;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    STATS_EXIT(statsPtWriteEmu);

    return status;
}


_Success_(return == INT_STATUS_SUCCESS)
INTSTATUS
IntHookPtwProcessWrite(
    _Inout_ PHOOK_PTEWS WriteState,
    _In_ QWORD Address,
    _In_ BYTE EntrySize,
    _Out_ QWORD *OldValue,
    _Out_ QWORD *NewValue
    )
///
/// @brief Processes a page-table write, returning the old and the new page-table entry value.
///
/// This function will process a page-table write and it will return the old and the new value inside that entry.
/// Unlike #IntHookPtwEmulateWrite, which emulates a raw write inside the page-table entry, this function works
/// with full page-table entry modifications: if a write is made only to a portion of the page-table entry, this
/// function will return #INT_STATUS_PARTIAL_WRITE and the callers can deffer processing this page-table write
/// until all remaining portions have been written as well. Example of a partial page-table write is PAE paging,
/// which implies 8 byte entries in 32 bit mode: usually, these will be modified using two 4 byte stores. Because
/// considering only one 4 byte write inside an 8 byte entry could lead to undefined behavior, Introcore waits
/// for an entire page-table entry to be written before handling the write.
/// NOTE: Occasionally, on Xen, we saw duplicate writes coming on the same page-table entry. On PAE paging, this
/// lead to undefined behavior. Therefore, we don't allow two consecutive writes from the same RIP, since this
/// indicates that a duplicate event was delivered.
///
/// @param[in, out] WriteState  The page-table write state.
/// @param[in]      Address     The written page-table entry (guest physical address).
/// @param[in]      EntrySize   The size of one page-table entry: 4 bytes (legacy paging) or 8 bytes (all other modes).
/// @param[out]     OldValue    Old page-table entry value.
/// @param[out]     NewValue    new page-table entry value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED If IntHookPtwEmulateWrite hasn't been already called for this write.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If it detects a duplicate write on the same portion of the entry.
/// @retval #INT_STATUS_PARTIAL_WRITE If only a portion of the page-table entry was written.
///
{
    INTSTATUS status;
    QWORD newValue, oldValue, byteOffs, bitMask, pteAddress;
    BYTE size, byteMask;

    if (NULL == WriteState)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == OldValue)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == NewValue)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pteAddress = Address & ~((QWORD)EntrySize - 1);

    // This exact PT entry write has already been emulated, and the new value is gVcpu->PtWriteCache.New. In this case,
    // we want to see if the new calculated value is the same as the current, known, entry inside this write state.
    // If they are the same, it means we are dealing with a PTE hook placed on an entry that was just written and
    // emulated, so the hook was placed with the correct, updated memory value - there is no need to call the swap
    // callbacks, as nothing actually changed.
    if (gVcpu->PtWriteCache.Valid &&
        gVcpu->PtWriteCache.PteAddress == pteAddress &&
        gVcpu->PtWriteCache.Value == WriteState->CurEntry)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsPtWriteProc);

    // We need to fetch the current value from the PT. We CAN'T use the intermediate value, because the A or D bits
    // may have been set (and we don't get notifications on A/D bits modifications made by the CPU, because we would
    // induce a high impact). Therefore, if the instruction that modifies the entry is a CMPXCHG, we would use a
    // wrong comparand (without the A/D bits set) and we would think that the source operand is not written into the
    // PTE, and therefore we would ignore the write. We could do a dirty hack and always assume that CMPXCHG writes
    // the value in memory, but this is equally risky because the PTE may have changed in the meantime and the value
    // may not be written, and we would basically have the opposite problem - we would think a write is being made,
    // when in fact it wouldn't be.

    // Align the accessed address to the size of one entry & get the offset inside the entry.
    byteOffs = Address & (EntrySize - 1);

    if (!gVcpu->PtEmuBuffer.Valid)
    {
        ERROR("[ERROR] Unhandled PT write!\n");
        IntEnterDebugger();
        status = INT_STATUS_NOT_INITIALIZED;
        goto cleanup_and_exit;
    }

    oldValue = gVcpu->PtEmuBuffer.Old;
    newValue = gVcpu->PtEmuBuffer.New;

    // Accessed size.
    size = (BYTE)gVcpu->AccessSize; // safe typecast: we know the size is <= 8.

    // XEN WORKAROUND: Check for duplicate writes.
    if (!gGuest.Guest64)
    {
        PIG_ARCH_REGS regs = &gVcpu->Regs;
        INSTRUX *instrux = &gVcpu->Instruction;

        // We don't allow 2 consecutive writes from the same RIP - these would indicate duplicate writes, which
        // break our internal state. We do allow consecutive writes from the same RIP if the size is 8 bytes, though.
        if (((regs->Rip & LAST_WRITE_RIP_MASK) == WriteState->LastWriteRip) && (0 == WriteState->LastWriteSize))
        {
            CHAR nd[ND_MIN_BUF_SIZE] = {0};
            NdToText(instrux, regs->Rip, sizeof(nd), nd);

            LOG("[PTWH] Possible duplicate write from RIP %llx (last RIP: %x), size %d, (last size: %d), "
                "entry %llx, cur %llx, int %llx, mask %x, instr: %s\n",
                regs->Rip, WriteState->LastWriteRip, size, WriteState->LastWriteSize, Address,
                WriteState->CurEntry, WriteState->IntEntry, WriteState->WrittenMask, nd);

            status = INT_STATUS_NOT_NEEDED_HINT;
            goto cleanup_and_exit;
        }

        WriteState->LastWriteRip = (DWORD)(regs->Rip & LAST_WRITE_RIP_MASK);
        WriteState->LastWriteSize = (size == 8) ? 1 : 0;
    }

    byteMask = ((1UL << size) - 1) << byteOffs;

    bitMask = gByteMaskToBitMask[byteMask];

    // Update the old, original value, if this is the first chunk written.
    if (0 == WriteState->WrittenMask)
    {
        WriteState->CurEntry = oldValue;
    }

    // Update the written mask.
    WriteState->WrittenMask |= byteMask;

    // Update our internal state.
    WriteState->IntEntry = (WriteState->IntEntry & ~bitMask) | ((newValue << (byteOffs * 8)) & bitMask);

    if (WriteState->WrittenMask != ((1UL << EntrySize) - 1))
    {
        status = INT_STATUS_PARTIAL_WRITE;
        goto cleanup_and_exit;
    }

    // The entire entry has been written, flag this appropriately.
    gVcpu->PtEmuBuffer.Partial = FALSE;

    *NewValue = WriteState->IntEntry;
    *OldValue = WriteState->CurEntry;

    WriteState->CurEntry = WriteState->IntEntry;
    WriteState->IntEntry = 0;

    WriteState->WrittenMask = 0;

    // Fill in the PT entry write cache. If a new hook is placed on this exact same PT entry, on this exact same exit,
    // we will know not to call the swap in callback, as the memory value used when placing the hook will be the same
    // as this new, written value.
    gVcpu->PtWriteCache.Valid = TRUE;
    gVcpu->PtWriteCache.PteAddress = pteAddress;
    gVcpu->PtWriteCache.Value = *NewValue;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    STATS_EXIT(statsPtWriteProc);

    return status;
}
