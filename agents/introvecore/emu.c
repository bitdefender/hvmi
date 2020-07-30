/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "emu.h"
#include "hviface.h"
#include "spinlock.h"
#include "vestatus.h"
#include "cache.h"


// These don't respect the global variable naming rule because they're actually exports.
QWORD VeCoreSelfMapIndex;    // The self-map index (NOT offset!) inside the PML4.
QWORD VeCoreMonitoredPtBits; // The bits we wish to monitor in page-tables. Changing any of them will trigger an exit.

// We have one lock for each possible PT entry. This allows us to avoid waiting for a lock on one VCPU which modifies
// an entry unrelated to an entry modified by another VCPU. For example, if VCPU1 is modifying PT offset 0x100, there
// is no point in waiting for the lock on VCPU3 if it's modifying PT offset 0x28. We take the locks using the index
// of the top-most page-table entry which is not self-map (basically, we lock an entire translation chain starting 
// with the modified PT entry).
SPINLOCK gLock[512];            // NOTE: Global data, will be 0-initialized, which is the lock init value also.

// NOTE: No 5 level paging support. HVI does not support it either, so this driver won't get to be injected if 5 level
// paging mode is detected. Also, no PAE or legacy 32 bit mode paging support either.
#define PML4_INDEX(gla)         (((gla) >> (12 + 9 + 9 + 9) & 0x1FF))
#define PDP_INDEX(gla)          (((gla) >> (12 + 9 + 9) & 0x1FF))
#define PD_INDEX(gla)           (((gla) >> (12 + 9) & 0x1FF))
#define PT_INDEX(gla)           (((gla) >> (12) & 0x1FF))


//
// VeLockUnlock
//
static void VeLockUnlock(
    QWORD Gla,
    BOOLEAN Acquire
    )
{
    // Place the lock at the top-most page-table entry which is not the self-map entry.
    QWORD pml4i, pdpi, pdi, pti, pfi, lockidx;

    pml4i = PML4_INDEX(Gla);
    pdpi = PDP_INDEX(Gla);
    pdi = PD_INDEX(Gla);
    pti = PT_INDEX(Gla);
    pfi = (Gla >> 3) & 0x1ff;

    if (pml4i != VeCoreSelfMapIndex)
    {
        // Not possible, normally...
        lockidx = pml4i;
    }
    else if (pdpi != VeCoreSelfMapIndex)
    {
        lockidx = pdpi;
    }
    else if (pdi != VeCoreSelfMapIndex)
    {
        lockidx = pdi;
    }
    else if (pti != VeCoreSelfMapIndex)
    {
        lockidx = pti;
    }
    else
    {
        lockidx = pfi;
    }

    if (Acquire)
    {
        SpinLockAcquire(&gLock[lockidx]);
    }
    else
    {
        SpinLockRelease(&gLock[lockidx]);
    }
}


#define LOCK(gla)       VeLockUnlock(gla, TRUE)
#define UNLOCK(gla)     VeLockUnlock(gla, FALSE)


//
// VeHandlePtWriteFast
//
VESTATUS
VeHandlePtWrite(
    PVECPU Cpu
    )
{
    NDSTATUS ndstatus = ND_STATUS_SUCCESS;
    INSTRUX instrux;
    PND_OPERAND memOp = NULL;
    QWORD gla = 0, flags = 0;

    // Decode the instruction.
    ndstatus = NdDecodeEx(&instrux, (PBYTE)Cpu->Registers.RIP, 16, ND_CODE_64, ND_DATA_64);
    if (!ND_SUCCESS(ndstatus))
    {
        if (ND_STATUS_BUFFER_TOO_SMALL == ndstatus)
        {
            return VE_STATUS_PAGE_NOT_PRESENT;
        }
        else
        {
            return VE_STATUS_DISASM_ERROR;
        }
    }

    // Do not handle repeated instructions, as they may write passed the page-table.
    // Also, ignore segment-prefixed or RIP relative instructions.
    // Also, ignore instructions which may modify the RSP, otherwise, we may end up being exploited via ROP.
    if (instrux.IsRepeated || instrux.HasSeg || instrux.IsRipRelative || instrux.StackAccess)
    {
        return VE_STATUS_NOT_SUPPORTED;
    }

    memOp = &instrux.Operands[0];

    // Make sure this instruction does in fact a memory write.
    if (memOp->Type != ND_OP_MEM)
    {
        return VE_STATUS_NOT_SUPPORTED;
    }

    // We can only handle 8 bytes writes.
    if (memOp->Size != 8)
    {
        return VE_STATUS_NOT_SUPPORTED;
    }

    // Make sure we fetched the proper instruction: we compute the instruction GLA and compare it to the GLA that the
    // CPU generated a #VE on. If they match, we're good to go.
#define REG(r) (*(&Cpu->Registers.RAX + (r)))

    if (memOp->Info.Memory.HasBase)
    {
        gla += ND_TRIM(memOp->Info.Memory.BaseSize, REG(memOp->Info.Memory.Base));
    }

    if (memOp->Info.Memory.HasIndex)
    {
        gla += ND_TRIM(memOp->Info.Memory.IndexSize, REG(memOp->Info.Memory.Index)) * memOp->Info.Memory.Scale;
    }

    if (memOp->Info.Memory.HasDisp)
    {
        gla += memOp->Info.Memory.Disp;
    }

    // Instruction GLA not the same as the faulted GLA - break;
    if (gla != Cpu->GuestLinearAddress)
    {
        return VE_STATUS_NOT_SUPPORTED;
    }

    // Modification not 8 bytes aligned - break.
    if ((gla & 0x7) != 0)
    {
        return VE_STATUS_NOT_SUPPORTED;
    }

    // IMPORTANT: The following operations must be performed in an atomic manner. The reason behind this is a 
    // possible race condition. Consider the following: a modification is made at PT entry GLA, but between the 
    // execution of the instruction and the fetch of the new value, some other thread modifies the GLA translation
    // and makes the PT invalid. This will lead to a crash, because the PT entry that we've just modified has become
    // invalid in the meantime, and the fetch of the new value will cause a #PF. This may happen, for example, if
    // the entry points to an empty PT and the MM decides it can remove it completely.
    // This applies also to the case where other PT modifications take place BEFORE allowing HVI to handle the 
    // modifications. As a result, we make the entire PT entry processing, including the HVI part, atomic.
    // In addition, we cannot commit the PT modification until HVI handles it. The reason behind this is because 
    // remapping may be done inside the #VE agent itself, and we must be careful when handling those, as all VCPUs
    // must be paused, and the contents of the remapped page must be copied manually by HVI, as the OS can't read the
    // #VE agent. In order to avoid PT entry modification atomicity issues, we use the global lock for the page 
    // walker as well, thus serializing the access into the entry.
    LOCK(gla);

    // Fetch the old value. NOTE: gla will never be NULL.
    if (0 != gla)
    {
        Cpu->OldValue = *((QWORD*)gla);
    }


    // We already made some validations, and we know that:
    // 1. The destination is memory
    // 2. The instruction GLA is the same as the accessed GLA
    // 3. The access size is 8 bytes
    // 4. No fancy stuff, like segment override, rep, RIP relative is used.
    // Therefore, it is safe to do this fast emulation here.
    if (instrux.Instruction == ND_INS_MOV)
    {
        if (instrux.Operands[1].Type == ND_OP_REG)
        {
            // MOV [mem], reg
            Cpu->NewValue = REG(instrux.Operands[1].Info.Register.Reg);
        }
        else if (instrux.Operands[1].Type == ND_OP_IMM)
        {
            // MOV [mem], imm
            Cpu->NewValue = instrux.Operands[1].Info.Immediate.Imm;
        }
        else
        {
            // Source is not reg, not imm, bail out.
            UNLOCK(gla);
            return VE_STATUS_NOT_SUPPORTED;
        }
    }
    else if (instrux.Instruction == ND_INS_STOS)
    {
        // STOSQ. We've already made sure the accessed size is 8 bytes.
        Cpu->NewValue = REG(NDR_RAX);
    }
    else if (instrux.Instruction == ND_INS_XCHG)
    {
        // XCHG [mem], reg
        Cpu->NewValue = REG(instrux.Operands[1].Info.Register.Reg);
        REG(instrux.Operands[1].Info.Register.Reg) = Cpu->OldValue;
    }
    else if (instrux.Instruction == ND_INS_CMPXCHG)
    {
        QWORD old;

        // CMPXCHG [mem], reg
        Cpu->NewValue = Cpu->OldValue;

        old = _InterlockedCompareExchange64((volatile long long *)&Cpu->NewValue, 
                                            REG(instrux.Operands[1].Info.Register.Reg), REG(NDR_RAX));

        flags = __readeflags();

        if ((flags & NDR_RFLAG_ZF) == 0)
        {
            // Values were not equal, load the old value in RAX.
            REG(NDR_RAX) = old;
        }
    }
    else if ((instrux.Instruction == ND_INS_XOR) || 
             (instrux.Instruction == ND_INS_AND) || 
             (instrux.Instruction == ND_INS_OR))
    {
        QWORD source = 0;

        if (instrux.Operands[1].Type == ND_OP_REG)
        {
            // XOR/AND/OR [mem], reg
            source = REG(instrux.Operands[1].Info.Register.Reg);
        }
        else if (instrux.Operands[1].Type == ND_OP_IMM)
        {
            // XOR/AND/OR [mem], imm
            source = instrux.Operands[1].Info.Immediate.Imm;
        }
        else
        {
            UNLOCK(gla);
            return VE_STATUS_NOT_SUPPORTED;
        }

        switch (instrux.Instruction)
        {
        case ND_INS_XOR:
            Cpu->NewValue = Cpu->OldValue ^ source;
            break;
        case ND_INS_AND:
            Cpu->NewValue = Cpu->OldValue & source;
            break;
        case ND_INS_OR:
            Cpu->NewValue = Cpu->OldValue | source;
            break;
        }
        
        flags = __readeflags();
    }
    else if ((instrux.Instruction == ND_INS_BTC) ||
             (instrux.Instruction == ND_INS_BTR) ||
             (instrux.Instruction == ND_INS_BTS))
    {
        QWORD bit;

        if (instrux.Operands[1].Type == ND_OP_REG)
        {
            // BTC/BTS/BTR [mem], reg
            bit = REG(instrux.Operands[1].Info.Register.Reg);
        }
        else if (instrux.Operands[1].Type == ND_OP_IMM)
        {
            // BTC/BTS/BTR [mem], imm
            bit = instrux.Operands[1].Info.Immediate.Imm;
        }
        else
        {
            UNLOCK(gla);
            return VE_STATUS_NOT_SUPPORTED;
        }

        bit = bit % 64;

        Cpu->NewValue = Cpu->OldValue;

        switch (instrux.Instruction)
        {
        case ND_INS_BTC:
            _bittestandcomplement64(&Cpu->NewValue, bit);
            break;
        case ND_INS_BTS:
            _bittestandset64(&Cpu->NewValue, bit);
            break;
        case ND_INS_BTR:
            _bittestandreset64(&Cpu->NewValue, bit);
            break;
        }

        flags = __readeflags();
    }
    else
    {
        UNLOCK(gla);
        return VE_STATUS_NOT_SUPPORTED;
    }

    // Transplant the modified flags.
    Cpu->Registers.RFLAGS = (Cpu->Registers.RFLAGS & ~instrux.FlagsAccess.Modified.Raw) | 
                            (flags & instrux.FlagsAccess.Modified.Raw);

    // Set the flags which are always set to 1.
    Cpu->Registers.RFLAGS |= instrux.FlagsAccess.Set.Raw;

    // Clear the flags which are always cleared to 0.
    Cpu->Registers.RFLAGS &= ~instrux.FlagsAccess.Cleared.Raw;

    // We don't care if any mapping or control bit is modified if both the old & new entries are invalid.
    if ((0 != ((Cpu->NewValue ^ Cpu->OldValue) & VeCoreMonitoredPtBits)) &&
        (0 != ((Cpu->NewValue & PT_P) + (Cpu->OldValue & PT_P))))
    {
        // only notify HVI if bit is set in #VE Cache Bitmap
        if (VeCacheIsEntryHooked(Cpu->GuestPhysicalAddress))
        {
            Cpu->Raised = 1;

            // Copy the instruction bytes inside the #VE info page.
            *(QWORD*)(&Cpu->Instruction[0]) = *(QWORD*)(&instrux.InstructionBytes[0]);
            *(QWORD*)(&Cpu->Instruction[8]) = *(QWORD*)(&instrux.InstructionBytes[8]);

            HvRaiseEpt();
        }
        else
        {
            _InterlockedIncrement64(&Cpu->VeIgnoredCache);
        }
    }
    else
    {
        _InterlockedIncrement64(&Cpu->VeIgnoredIrrelevant);
    }

    // Store the new value inside the page-table. NOTE: gla will never be 0.
    if (0 != gla)
    {
        *((QWORD*)gla) = Cpu->NewValue;
    }

    UNLOCK(gla);

    Cpu->Registers.RIP += instrux.Length;

    return VE_STATUS_SUCCESS;
}


//
// VeGetPteGla
//
__forceinline
QWORD
VeGetPteGla(
    QWORD Gla
    )
{
    QWORD pte = 0xFFFF000000000000ULL;

    // Store the PML4 self-map index.
    pte |= VeCoreSelfMapIndex << (12 + 9 + 9 + 9);

    // Store the PDP index.
    pte |= (PML4_INDEX(Gla) << (12 + 9 + 9));

    // Store the PD index.
    pte |= (PDP_INDEX(Gla) << (12 + 9));

    // Store the PT index.
    pte |= (PD_INDEX(Gla) << (12));

    // Store the page offset.
    pte |= PT_INDEX(Gla) << 3;

    return pte;
}


//
// VeGetPdeGla
//
__forceinline
QWORD
VeGetPdeGla(
    QWORD Gla
    )
{
    QWORD pde = 0xFFFF000000000000;

    // Store the PML4 self-map index.
    pde |= VeCoreSelfMapIndex << (12 + 9 + 9 + 9);

    // Store the PDP index.
    pde |= VeCoreSelfMapIndex << (12 + 9 + 9);

    // Store the PD index.
    pde |= (PML4_INDEX(Gla) << (12 + 9));

    // Store the PT index.
    pde |= (PDP_INDEX(Gla) << (12));

    // Store the page offset.
    pde |= (PD_INDEX(Gla) << (3));

    return pde;
}


//
// VeGetPdpeGla
//
__forceinline
QWORD
VeGetPdpeGla(
    QWORD Gla
    )
{
    QWORD pdpe = 0xFFFF000000000000;

    // Store the PML4 self-map index.
    pdpe |= VeCoreSelfMapIndex << (12 + 9 + 9 + 9);

    // Store the PDP index.
    pdpe |= VeCoreSelfMapIndex << (12 + 9 + 9);

    // Store the PD index.
    pdpe |= VeCoreSelfMapIndex << (12 + 9);

    // Store the PT index.
    pdpe |= (PML4_INDEX(Gla) << (12));

    // Store the page offset.
    pdpe |= (PDP_INDEX(Gla) << (3));

    return pdpe;
}


//
// VeGetPml4eGla
//
__forceinline
QWORD
VeGetPml4eGla(
    QWORD Gla
    )
{
    QWORD gla = 0xFFFF000000000000;

    // Store the PML4 self-map index.
    gla |= VeCoreSelfMapIndex << (12 + 9 + 9 + 9);

    // Store the PDP index.
    gla |= VeCoreSelfMapIndex << (12 + 9 + 9);

    // Store the PD index.
    gla |= VeCoreSelfMapIndex << (12 + 9);

    // Store the PT index.
    gla |= VeCoreSelfMapIndex << (12);

    // Store the page offset.
    gla |= (PML4_INDEX(Gla) << (3));

    return gla;
}


//
// VeLockSetBits
//
void __inline
VeLockSetBits(
    QWORD *Address,
    QWORD Value,
    QWORD Mask
    )
{
    QWORD oldValue;

    LOCK((QWORD)Address);

    while (1)
    {
        if (Value & PT_P)
        {
            // Only if the entry is present.

            oldValue = _InterlockedCompareExchange64(Address, Value | Mask, Value);

            if (oldValue == Value)
            {
                // Exchange successful.
                break;
            }
            else
            {
                // Couldn't do it the first time, try again, but this time with the new comparand.
                Value = oldValue;
            }
        }
        else
        {
            break;
        }
    }

    UNLOCK((QWORD)Address);
}


//
// VeHandlePageWalk
//
VESTATUS
VeHandlePageWalk(
    PVECPU Cpu
    )
{
    QWORD *pml4e = NULL, *pdpe = NULL, *pde = NULL, *pte = NULL, *leaf = NULL;
    BOOLEAN setall = TRUE;

    //
    // Do the page walk & set the A/D bits as needed.
    // The A bit will always be set in all page-table levels.
    // The D bit will be set only if the last level page table entry is already Accessed AND the page is writable.
    //

    // Get the PML4 entry and set the A bit.
    pml4e = (QWORD*)VeGetPml4eGla(Cpu->GuestLinearAddress);
    if (0 == (*pml4e & PT_P))
    {
        goto cleanup_and_exit;
    }

    if (0 == (*pml4e & PT_A))
    {
        setall = FALSE;

        VeLockSetBits(pml4e, *pml4e, PT_A);
    }


    // Get the PDP entry and set the A bit.
    pdpe = (QWORD*)VeGetPdpeGla(Cpu->GuestLinearAddress);
    if (0 == (*pdpe & PT_P))
    {
        goto cleanup_and_exit;
    }

    // Handle 1GB page.
    if (0 != (*pdpe & PT_PS))
    {
        leaf = pdpe;
        goto handle_leaf;
    }

    if (0 == (*pdpe & PT_A))
    {
        setall = FALSE;

        VeLockSetBits(pdpe, *pdpe, PT_A);
    }


    // Get the PD entry and set the A bit.
    pde = (QWORD*)VeGetPdeGla(Cpu->GuestLinearAddress);
    if (0 == (*pde & PT_P))
    {
        goto cleanup_and_exit;
    }

    // Handle 2MB page.
    if (0 != (*pde & PT_PS))
    {
        leaf = pde;
        goto handle_leaf;
    }

    if (0 == (*pde & PT_A))
    {
        setall = FALSE;

        VeLockSetBits(pde, *pde, PT_A);
    }


    // Get the PT entry and set the A bit.
    pte = (QWORD*)VeGetPteGla(Cpu->GuestLinearAddress);
    if (0 == (*pte & PT_P))
    {
        goto cleanup_and_exit;
    }

    leaf = pte;

handle_leaf:
    // If the leaf entry is already accessed and it is writable or CR0.WP is not set, then also set the dirty flag.
    if ((0 != (*leaf & PT_A)) && ((0 != (*leaf & PT_RW)) || (0 == (Cpu->Registers.CR0 & CR0_WP))))
    {
        if (0 == (*leaf & PT_D))
        {
            setall = FALSE;
        }

        VeLockSetBits(leaf, *leaf, PT_D);
    }

    if (0 == (*leaf & PT_A))
    {
        setall = FALSE;

        VeLockSetBits(leaf, *leaf, PT_A);
    }


    if (setall && 0 == (Cpu->GuestLinearAddress & 0x8000000000000000))
    {
        // The A bit is set in all the levels, so there are two possibilities:
        // 1. Either we incurred a spurious page-walk fault, in which case, all is good
        // 2. Either KPTI is activated, and we just did the page-walk for a user-mode address, using the kernel CR3,
        //    while the user CR3 PML4 is NOT accessed. We will invoke HVI, to set the A bit for the user CR3 PML4.
        // Note that we invoke HVI only for user-mode GLAs.
        Cpu->Raised = TRUE;

        HvRaiseEpt();
    }

cleanup_and_exit:

    return VE_STATUS_SUCCESS;
}
