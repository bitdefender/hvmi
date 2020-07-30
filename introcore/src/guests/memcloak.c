/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
/// @addtogroup group_memclk
/// @{

#include "memcloak.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"

///
/// @brief  A structure that describes a hidden guest memory page.
///
typedef struct _MEMCLOAK_PAGE
{
    DWORD           DataOffset;         ///< Offset inside the data buffer.
    DWORD           PageStartOffset;    ///< Offset at which the data starts in this page.
    DWORD           PageEndOffset;      ///< Offset at which the data ends in this page.
    void           *SwapHook;           ///< The swap handle.
    void           *ReadHook;           ///< The read hook handle.
    void           *WriteHook;          ///< The write hook handle.
    void           *Region;             ///< The parent #MEMCLOAK_REGION region.
} MEMCLOAK_PAGE, *PMEMCLOAK_PAGE;

#define MEMCLOACK_PAGE_MAX_COUNT    2   ///< The maximum number of pages that can be contained in a #MEMCLOAK_REGION.

///
/// @brief  A structure that describes a hidden guest memory region.
typedef struct _MEMCLOAK_REGION
{
    LIST_ENTRY      Link;               ///< Entry inside the #gMemClkRegions linked list.
    QWORD           Gva;                ///< The guest virtual address at which the hidden region starts.
    QWORD           Cr3;                ///< The Cr3 in which the hidden region is mapped.
    DWORD           Size;               ///< The size of the hidden region. OriginalData and PatchedData have this size.
    DWORD           Options;            ///< A combination of #MEMCLOAK_OPTIONS values.
    PBYTE           OriginalData;       ///< A buffer containing the original data.
    PBYTE           PatchedData;        ///< A buffer containing the data patched by introcore.

    /// @brief  Array of pages contained in this region.
    ///
    /// Hidden region can cross the page boundary, in which case we will have two pages included in a single region.
    MEMCLOAK_PAGE   Pages[MEMCLOACK_PAGE_MAX_COUNT];
    DWORD           PageCount;          ///< The number of valid entries in the Pages array.

    /// @brief  The write handler used for this region.
    ///
    /// This will be invoked when the guest attempts to modify a hidden memory region.
    PFUNC_IntMemCloakWriteHandle WriteHandler;
} MEMCLOAK_REGION, *PMEMCLOAK_REGION;

/// @brief  A list containing all the memory regions that are currently hidden from the guest.
static LIST_HEAD gMemClkRegions = LIST_HEAD_INIT(gMemClkRegions);


static INTSTATUS
IntMemClkUncloakRegionInternal(
    _In_ DWORD Options,
    _Inout_ PMEMCLOAK_REGION Region
    );

static INTSTATUS
IntMemClkHandleSwap(
    _Inout_ MEMCLOAK_PAGE *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief  Handles swap-in and swap-outs performed on hidden memory regions.
///
/// On swap-in operations, we have to ensure that the patched data is restored. Otherwise, after a swap-out,
/// the original content of the page would be restored, leading to the loss of the patched data.
///
/// @param[in]  Context         The page for which this handler is invoked.
/// @param[in]  VirtualAddress  The guest virtual address for which this handler is invoked.
/// @param[in]  OldEntry        The old page table entry used to translate VirtualAddress.
/// @param[in]  NewEntry        The new page table entry used to translate VirtualAddress.
/// @param[in]  OldPageSize     The old page size.
/// @param[in]  NewPageSize     The new page size.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///

{
    INTSTATUS status;
    PMEMCLOAK_REGION pCloak;
    PMEMCLOAK_PAGE pPage;
    DWORD oldPgOffs, newPgOffs, internalOffset, size;
    QWORD oldPhysAddr, newPhysAddr;
    BOOLEAN oldValid,  newValid;

    status = INT_STATUS_SUCCESS;

    // Fetch the context
    pPage = Context;
    pCloak = (PMEMCLOAK_REGION)pPage->Region;

    // Get the physical page address.
    oldPhysAddr = CLEAN_PHYS_ADDRESS64(OldEntry) & (~(OldPageSize - 1));
    newPhysAddr = CLEAN_PHYS_ADDRESS64(NewEntry) & (~(NewPageSize - 1));

    oldValid = (OldEntry & 1);
    newValid = (NewEntry & 1);

    // If nothing interesting changed, bail out.
    if ((!oldValid && !newValid) || ((oldValid && newValid && (oldPhysAddr == newPhysAddr))))
    {
        return INT_STATUS_SUCCESS;
    }

    // Compute the offset inside the current page of the cloaked data.
    if ((pCloak->Gva & PAGE_MASK) ==
        ((pCloak->Gva + pCloak->Size - 1) & PAGE_MASK))
    {
        // The cloaked region is contained within the same 4K page. This is the simplest case. Note that we use
        // 4K pages for this test because they're the smallest entity that can be translated by the CPU.
        oldPgOffs = (DWORD)(pCloak->Gva & (OldPageSize - 1));
        newPgOffs = (DWORD)(pCloak->Gva & (NewPageSize - 1));

        internalOffset = 0;

        size = pCloak->Size;
    }
    else
    {
        // Hook spills multiple pages. Handle each case. Note that we use PAGE_SIZE and PAGE_MASK because we place
        // hooks on 4K pages: even if the pages will be remapped as a large 2M page, this callback will be invoked
        // for each 4K page individually.
        if ((pCloak->Gva & PAGE_MASK) == (VirtualAddress & PAGE_MASK))
        {
            // The first page written. This also covers the above case.
            oldPgOffs = (DWORD)(pCloak->Gva & (OldPageSize - 1));
            newPgOffs = (DWORD)(pCloak->Gva & (NewPageSize - 1));

            internalOffset = 0;

            size = (DWORD)MIN(PAGE_REMAINING(pCloak->Gva), pCloak->Size);
        }
        else
        {
            // Another page written.
            oldPgOffs = (DWORD)(((pCloak->Gva & PAGE_MASK) + PAGE_SIZE) & (OldPageSize - 1));
            newPgOffs = (DWORD)(((pCloak->Gva & PAGE_MASK) + PAGE_SIZE) & (NewPageSize - 1));

            internalOffset = (DWORD)((VirtualAddress & PAGE_MASK) - pCloak->Gva);

            size = MIN(PAGE_SIZE, pCloak->Size - internalOffset);
        }
    }

    // Even if the old page and the new page have different sizes, the internalOffset will be the same, since we
    // align the accesses to 4K (we always deal with 4K pages).

    if ((internalOffset >= pCloak->Size) || (internalOffset + size > pCloak->Size) || (size > pCloak->Size))
    {
        ERROR("[ERROR] Invalid state: internalOffset = %d, size = %d, total size = %d\n",
              internalOffset, size, pCloak->Size);
        IntDbgEnterDebugger();
    }

    TRACE("[MEMCLOAK] Translation modification, VA = 0x%016llx, OldEntry = 0x%016llx, NewEntry = 0x%016llx, "
          "OldSize = 0x%016llx, NewSize = 0x%016llx, OldOffs = %x, NewOffs = %x, size = %d\n",
          VirtualAddress, OldEntry, NewEntry, OldPageSize, NewPageSize, oldPgOffs, newPgOffs, size);

    TRACE("[MEMCLOAK] Will patch at GPA %llx/%llx offset %x/%x, size %d, int offset %d, [GVA1: %llx GVA2: %llx]\n",
          oldPhysAddr, newPhysAddr, oldPgOffs, newPgOffs, size,
          internalOffset, pCloak->Gva, VirtualAddress);

    if (oldValid)
    {
        status = IntPhysicalMemWrite(oldPhysAddr + oldPgOffs, size, &pCloak->OriginalData[internalOffset]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysicalMemWrite failed: 0x%08x\n", status);
        }
    }

    if (newValid)
    {
        // Old entry was not present, the new one is.
        status = IntPhysicalMemWrite(newPhysAddr + newPgOffs, size, &pCloak->PatchedData[internalOffset]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysicalMemWrite failed: 0x%08x\n", status);
        }
    }

    return status;
}


static INTSTATUS
IntMemClkHandleRead(
    _Inout_ MEMCLOAK_PAGE *Context,
    _In_ PHOOK_GPA Hook,
    _In_ QWORD Gpa,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles reads from a hidden memory region.
///
/// This is were the actual hiding takes place. When trying to read from a memory area that is hidden, the guest
/// will generate an EPT violation VMEXIT that will be handled here.
/// This is done using the #GLUE_IFACE.SetIntroEmulatorContext mechanism, providing the underlying hypervisor the
/// data that needs to be used when emulating the access done by the guest.
/// In order to do this, we need to figure out where exactly inside the cloaked region is the read done and extract
/// the appropriate parts of the #MEMCLOAK_REGION.OriginalData buffer.
/// A read can overlap the hidden memory region in multiple way. If the hidden region is in the range [0x1002, 0x1006],
/// the read can be done for:
///     - the entire region: this is the easiest case, we can return the entire #MEMCLOAK_REGION.OriginalData buffer
///     - a part of the region (for example in the range [0x1003, 0x1004]): this is slightly more complicated, as we
///     now have to compute the offset of the read relative to the start of the region and return only that part
///     of the #MEMCLOAK_REGION.OriginalData buffer
///     - half inside the region, half outside of it (for example, [0x1000, 0x10004], or [0x1005, 0x1009]), in which
///     case a part of the returned patch buffer needs to contain the information that is already present inside the
///     guest memory, as that is not hidden, and the other part needs to be taken from the original data buffer
/// These scenarios get a bit more complicated when the region or the read crosses a page boundary.
/// If our region is split across two pages, but the read only accesses one of them, the above scenarios apply.
/// If a read crosses a page boundary it is important to decode the instruction that actually does the access and
/// obtain the linear virtual address accessed by that instruction, otherwise we may return wrong values. For example,
/// if the read starts at 0xfff, but we only hooked the page 0x1000, the virtual address reported in the VMEXIT
/// information will be 0x1000, but our emulation must start at 0xfff.
///
/// @param[in]  Context     The page for which this handler is invoked.
/// @param[in]  Hook        The GPA hook which triggered this event.
/// @param[in]  Gpa         The guest physical address that was accessed.
/// @param[out] Action      The action that must be taken while handling this event. This will be set to
///                         #introGuestAllowedPatched if there is something that must be hidden from the guest. If
///                         #introGuestAllowed is used, this can mean a few things: the accessed page is no longer
///                         present, in which case we want to allow the read, as it will generate a page fault inside
///                         the guest, which will handle it; or, we decided to allow the read (usually, due to the
///                         #MEMCLOAK_OPT_ALLOW_INTERNAL option).
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    PIG_ARCH_REGS regs;
    PMEMCLOAK_REGION pClkReg;
    PMEMCLOAK_PAGE pClkPage;
    PPATCH_BUFFER pb;
    PINSTRUX instrux;
    INTSTATUS status;
    DWORD patchSize, origCodeOffset, retBufOffset, readSize;
    QWORD gla;
    PHOOK_GVA pGva;
    DWORD startReadOffset, endReadOffset;
    DWORD glaOffset, gpaOffset;

    // Fetch the cloak region pointer.
    pClkPage = Context;
    pClkReg = (PMEMCLOAK_REGION)pClkPage->Region;

    *Action = introGuestAllowed;

    pGva = (PHOOK_GVA)Hook->Header.ParentHook;
    if (NULL == pGva)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (pGva->Header.HookType != hookTypeGva)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // Get the register state
    regs = &gVcpu->Regs;
    instrux = &gVcpu->Instruction;
    pb = &gVcpu->PatchBuffer;

    // In certain situations when the GLA is page-aligned it can't be trusted
    // Let's say we have a cloak region starting at 0x1006 and the guest starts a read on 0xffc with size 8
    // This will end at 0x1004, not even touching our region, but the CPU may report 0x1000 as the faulting GLA
    // So take the GLA from the instruction instead
    // This is not needed on Napoca due to the way read accessed are handled. On Xen, a read is emulated, so we need
    // to supply the actual value for the operand of the offending instruction, on Napoca the read is single stepped
    // so the contents are copied inside the guest starting with the offending GLA
    status = IntDecDecodeSourceLinearAddressFromInstruction(instrux, regs, &gla);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeSourceLinearAddressFromInstruction failed: 0x%08x\n", status);
        return status;
    }

    // If reads are allowed to be performed from within the cloaked region, bail out.
    if ((0 != (pClkReg->Options & MEMCLOAK_OPT_ALLOW_INTERNAL)) &&
        ((regs->Rip >= pClkReg->Gva) && (regs->Rip < pClkReg->Gva + pClkReg->Size)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    readSize = gVcpu->AccessSize;
    glaOffset = gla & PAGE_OFFSET;
    gpaOffset = Gpa & PAGE_OFFSET;

    if ((0 == readSize) || (readSize > ND_MAX_REGISTER_SIZE))
    {
        CHAR instrText[ND_MIN_BUF_SIZE] = {0};

        NdToText(instrux, regs->Rip, ND_MIN_BUF_SIZE, instrText);

        ERROR("[MEMCLOAK] [ERROR] Couldn't find the source memory operand for instruction at RIP 0x%016llx '%s'!\n",
              regs->Rip, instrText);

        IntDbgEnterDebugger();

        return INT_STATUS_NOT_SUPPORTED;
    }

    // Read the actual bytes form the guest. We will patch below with the original bytes. Note that if the patch-buffer
    // has already been initialized, it simply means that this is an access that touches multiple cloaks (example,
    // inside the kernel slack space, where the detour handlers are closely packed together).
    if (!pb->Valid)
    {
        status = IntVirtMemRead(gla, readSize, regs->Cr3, pb->Data, NULL);
        if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
        {
            *Action = introGuestAllowed;
            return INT_STATUS_SUCCESS;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed for GPA 0x%016llx with size %d: 0x%08x\n", gla, readSize, status);
            return status;
        }

        pb->Gla = gla;
        pb->Size = readSize;
        pb->Valid = TRUE;
    }
    else if (pb->Gla != gla)
    {
        // The access was already handled. This can happen if the access spans inside two pages, because we call the
        // handlers for each accessed page. For example, if we have a read at 0x1FFC with size 8, this callback will
        // be called two times: the first time with GLA = 0x1FFC and size 8, and the second time with GLA = 0x2000 and
        // size 4. Since the read was already handled the first time this callback was called, we can safely bail out.
        // Note that if the patch buffer is valid we may still have to handle this access, as the read may span multiple
        // cloaks, but on those cases, the patch buffer and the current GLAs will always be the same.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    startReadOffset = gpaOffset;
    endReadOffset = startReadOffset + readSize;

    //
    // There are a few cases that must be supported, which can be summarized as:
    //  If the cloak sub-region is: [cStart, cEnd) and the read region is [rStart, rEnd), we can combine them as:
    //      1. rStart < cStart < rEnd < cEnd (starts before the sub-region, ends inside it)
    //      2. rStart < cStart < cEnd < rEnd (starts before the sub-region, ends after it)
    //      3. cStart < rStart < rEnd < cEnd (starts inside the sub-region, ends inside it)
    //      4. cStart < rStart < cEnd < rEnd (starts inside the sub-region, ends after it)
    //  Note that rEnd < cStart (read ends before the start of the sub-region) and cEnd < rStart (read starts after the
    // end of the sub-region) are handled by the hooking mechanism and this callback is never invoked in those cases
    //  The above examples can get more complicated when dealing with page boundary issues, mainly: a read that starts
    // in one page and ends in the next one, touches a sub-region contained only in the next page: this is true when a
    // region is split across two pages (so it is contained in two sub-regions) or when it starts at the page start
    //

    if (glaOffset == gpaOffset)
    {
        // The access starts in the same page as the hooked page
        // The read ends in the next page, but we care only about the current one
        if (endReadOffset > PAGE_SIZE)
        {
            // The read ends at the end of this page
            endReadOffset = PAGE_SIZE;
            // Ignore anything that is read from the next page
            readSize = endReadOffset - startReadOffset;
        }

        if (startReadOffset < pClkPage->PageStartOffset)
        {
            // The read starts before the cloak
            origCodeOffset = 0 + pClkPage->DataOffset;
            retBufOffset = pClkPage->PageStartOffset - startReadOffset;
            // The read either ends inside the sub-region or after it ends, give back the minimum between the sub-region
            // size and the read size (ignoring everything that comes before the sub-region)
            patchSize = MIN(endReadOffset - pClkPage->PageStartOffset,
                            pClkPage->PageEndOffset - pClkPage->PageStartOffset);
        }
        else
        {
            // The read starts inside the sub-region
            origCodeOffset = startReadOffset - pClkPage->PageStartOffset + pClkPage->DataOffset;
            retBufOffset = 0;
            // The read either ends inside the sub-region or after it ends, give back the minimum between the sub-region
            // size and the read size (ignoring everything that comes before the sub-region)
            patchSize = MIN(endReadOffset - startReadOffset, pClkPage->PageEndOffset - startReadOffset);
        }
    }
    else
    {
        DWORD readInPrevPage;

        // The access starts in a page, but the hook is in the next one
        // Advance the read start to the next page
        startReadOffset = gpaOffset;
        // Recalculate the read size and the read end offset to ignore anything from the previous page
        readSize -= (PAGE_SIZE - glaOffset);
        endReadOffset = startReadOffset + readSize;
        // Remember what was read in the previous page
        readInPrevPage = gVcpu->AccessSize - readSize;

        if (startReadOffset <= pClkPage->PageStartOffset)
        {
            // The read starts before the cloak
            origCodeOffset = 0 + pClkPage->DataOffset;
            // Keep in mind that the instruction reads data from two pages, but pClkPage->PageStartOffset and
            // startReadOffset refer only to the current page
            retBufOffset = pClkPage->PageStartOffset - startReadOffset + readInPrevPage;
            // The read either ends inside the sub-region or after it ends, give back the minimum between the sub-region
            // size and the read size (ignoring everything that comes before the sub-region)
            patchSize = MIN(endReadOffset - pClkPage->PageStartOffset,
                            pClkPage->PageEndOffset - pClkPage->PageStartOffset);
        }
        else
        {
            // The read starts inside the cloak sub-range. This shouldn't happen as the read starts in the previous page
            // and the sub-range starts in the current page

            CHAR text[ND_MIN_BUF_SIZE] = { 0 };

            NdToText(instrux, regs->Rip, ND_MIN_BUF_SIZE, text);

            LOG("[MEMCLOAK] This should not happen\n");
            LOG("[MEMCLOAK] [CPU %d] From RIP 0x%016llx with instruction '%s', RegSize %d, GPA 0x%016llx, "
                "MemSize %d, access 0x%016llx/%d [0x%08x, 0x%08x) -> [0x%08x: 0x%08x, 0x%08x)\n",
                gVcpu->Index, regs->Rip, text, instrux->Operands[0].Size, Gpa,
                instrux->Operands[1].Size, gla, readSize, startReadOffset, endReadOffset,
                pClkPage->DataOffset, pClkPage->PageStartOffset, pClkPage->PageEndOffset);
            IntEnterDebugger();

            origCodeOffset = retBufOffset = patchSize = 0;
        }
    }

    if (startReadOffset < pClkPage->PageEndOffset &&
        endReadOffset > pClkPage->PageStartOffset)
    {
        // Patch the return buffer only if the guest read overlaps with the region guarded by this cloak page
        // This can happen as in the above case when the region starts at 0x1006 and and 8 bytes read starts at 0xffc,
        // but it is reported as being done for [0x1000, 0x10008), when in fact it does not overlap the region
        memcpy(&pb->Data[retBufOffset], &pClkReg->OriginalData[origCodeOffset], patchSize);
    }

#ifdef DEBUG

    TRACE("[MEMCLOAK] Handled the access on 0x%016llx/0x%016llx with retBufOffset = 0x%08x, "
          "origCodeOffset = 0x%08x, patchSize = 0x%08x\n",
          gla, Gpa, retBufOffset, origCodeOffset, patchSize);

    IntDumpBuffer(pb->Data, pb->Gla, pb->Size, 16, 1, TRUE, TRUE);

#endif // DEBUG

    *Action = introGuestAllowedPatched;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntMemClkHandleWrite(
    _In_ PMEMCLOAK_PAGE *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles writes done inside a hidden memory region.
///
/// Each region can have its own write handler that can decide the action that must be taken for this event. If no
/// custom write handler is provided, the write is always blocked, as we don't want our code and data to be changed
/// by the guest.
/// Also, even in situations in which we want to allow writes, we must place an EPT write hook for the hidden pages
/// as removing only the read permission from the EPT will cause the EPT rights to be write-execute, which is
/// an invalid combination.
///
/// @param[in]  Context     The page for which this handler is invoked.
/// @param[in]  Hook        The hook for which this handler is invoked. It simply passes it further to the custom
///                         handler, if one exists.
/// @param[in]  Address     The physical address accessed.
/// @param[out] Action      The action that must be taken. The default value is #introGuestNotAllowed for regions
///                         that do not have a custom write handler.
///
/// @returns    #INT_STATUS_FORCE_ACTION_ON_BETA regardless of what errors are encountered. The only possible failure
///             point is represented by the custom write handler, in which case it is ignored and the default action
///             will be taken. We need #INT_STATUS_FORCE_ACTION_ON_BETA in order to be sure that even if introcore
///             is in log-only mode, the write will be blocked if necessary.
///
{
    INTSTATUS status;
    MEMCLOAK_REGION *pClkRegion;

    pClkRegion = (MEMCLOAK_REGION *)((MEMCLOAK_PAGE *)Context)->Region;

    // By default, any writes inside a memcloak should be denied.
    // This may be overwritten by the region's write handler.
    *Action = introGuestNotAllowed;

    if (NULL != pClkRegion->WriteHandler)
    {
        status = pClkRegion->WriteHandler(Hook, Address, pClkRegion->Gva, pClkRegion, Action);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Memcloak write handler failed for virtual address 0x%llx. Status: 0x%08x\n",
                    Address, status);
        }
    }

    // Force the returned action, on beta. We must deny writes inside the hooked portions, even on beta!
    return INT_STATUS_FORCE_ACTION_ON_BETA;
}


void
IntMemClkCleanup(
    _Inout_ MEMCLOAK_REGION *Region
    )
///
/// @brief  Frees any resources held by a #MEMCLOAK_REGION.
///
/// This function will free the #MEMCLOAK_REGION.OriginalData and #MEMCLOAK_REGION.PatchedData buffers, as well as the
/// Region itself. It does not remove the hooks set for a region.
///
/// @param[in, out] Region  The region to be freed. This pointer is no longer valid after this function returns.
///
{
    if (NULL != Region->OriginalData)
    {
        HpFreeAndNullWithTag(&Region->OriginalData, IC_TAG_MCBF);
    }

    if (NULL != Region->PatchedData)
    {
        HpFreeAndNullWithTag(&Region->PatchedData, IC_TAG_MCBF);
    }

    HpFreeAndNullWithTag(&Region, IC_TAG_MCRG);
}


INTSTATUS
IntMemClkCloakRegion(
    _In_ QWORD VirtualAddress,
    _In_ QWORD Cr3,
    _In_ DWORD Size,
    _In_ DWORD Options,
    _In_opt_ PBYTE OriginalData,
    _In_opt_ PBYTE PatchedData,
    _In_opt_ PFUNC_IntMemCloakWriteHandle WriteHandler,
    _Out_ void **CloakHandle
    )
///
/// @brief  Hides a memory zone from the guest.
///
/// This will place an EPT read, EPT write hook on the [VirtualAddress, VirtualAddress + Size) memory region.
/// The read hook will allow us to hide memory from the guest. Attempts to read from the hidden pages will trigger an
/// EPT violation that will be handled by #IntMemClkHandleRead. This will allow us to control what the guest sees
/// from a memory page. This is helpful when trying to hide code or data injected by us inside the guest.
/// The write hook will allow us to protect the code or data injected inside the guest. It has a second purpose, as
/// only removing the read permission from the EPT is not allowed, write-execute being an invalid combination. The
/// write will be handled by #IntMemClkHandleWrite, but a custom WriteHandler can also be provided.
/// It will also hook the page tables used to translate the hidden pages, in order to catch swaps done on those pages
/// and make sure that the modified data does not leak during page swap-in. The swap operation will be handled by
/// #IntMemClkHandleSwap.
///
/// @param[in]  VirtualAddress      The start of the virtual memory region to be hidden.
/// @param[in]  Cr3                 The virtual address space in which the hiding is done.
/// @param[in]  Size                The size of the hidden region.
/// @param[in]  Options             Options that control the way accesses to the memory region are handled. Must be
///                                 0 or a combination of #MEMCLOAK_OPTIONS values.
/// @param[in]  OriginalData        The original data. This will be presented to the guest when it tries to read
///                                 from the cloaked area. If not NULL, it must be Size bytes in length. If it is NULL,
///                                 the original data is considered to be 0.
/// @param[in]  PatchedData         The data patched by Introcore inside the guest.If not NULL, it must be Size bytes
///                                 in length. If it is NULL, the patched data is considered to be 0.
/// @param[in]  WriteHandler        A custom handler to use when the guest tries to write to the hidden memory area.
///                                 It may be NULL, in which case the default handler will be used and all writes will
///                                 be blocked.
/// @param[out] CloakHandle         The handle of the cloaked region. This is used as an unique identifier by APIs
///                                 that control or modify the cloaked region.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the region spans across more than #MEMCLOACK_PAGE_MAX_COUNT pages.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if an internal buffer could not be allocated.
/// @retval     #INT_STATUS_INVALID_PARAMETER_8 if CloakHandle is NULL.
///
{
    INTSTATUS status;
    PMEMCLOAK_REGION pClkReg;
    DWORD leftToHook;
    DWORD pageCount;

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_8;
    }

    leftToHook = Size;
    pageCount = ((((VirtualAddress + Size - 1) & PAGE_MASK) - (VirtualAddress & PAGE_MASK)) / PAGE_SIZE) + 1;

    if (pageCount > MEMCLOACK_PAGE_MAX_COUNT)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    pClkReg = HpAllocWithTag(sizeof(*pClkReg), IC_TAG_MCRG);
    if (NULL == pClkReg)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InsertTailList(&gMemClkRegions, &pClkReg->Link);

    if (0 == Cr3)
    {
        Cr3 = gGuest.Mm.SystemCr3;
    }

    pClkReg->Gva = VirtualAddress;
    pClkReg->Cr3 = Cr3;
    pClkReg->Size = Size;
    pClkReg->Options = Options;
    pClkReg->WriteHandler = WriteHandler;

    pClkReg->OriginalData = HpAllocWithTag(Size, IC_TAG_MCBF);
    if (NULL == pClkReg->OriginalData)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    pClkReg->PatchedData = HpAllocWithTag(Size, IC_TAG_MCBF);
    if (NULL == pClkReg->PatchedData)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    // Now copy the original data inside the internal buffer.
    if (NULL != OriginalData)
    {
        memcpy(pClkReg->OriginalData, OriginalData, Size);
    }

    // And the patched data.
    if (NULL != PatchedData)
    {
        memcpy(pClkReg->PatchedData, PatchedData, Size);
    }

    for (QWORD va = VirtualAddress; va < VirtualAddress + Size;)
    {
        DWORD hookLen = MIN(leftToHook, PAGE_REMAINING(va));
        PMEMCLOAK_PAGE pClkPage = &pClkReg->Pages[pClkReg->PageCount++];

        leftToHook -= hookLen;

        pClkPage->Region = pClkReg;
        pClkPage->DataOffset = (DWORD)(va - VirtualAddress);
        pClkPage->PageStartOffset = va & PAGE_OFFSET;
        pClkPage->PageEndOffset = pClkPage->PageStartOffset + hookLen;

        // Swap hook. The callback will be called on translation changes.
        status = IntHookGvaSetHook(Cr3, va, hookLen, IG_EPT_HOOK_NONE, IntMemClkHandleSwap,
                                   pClkPage, NULL, HOOK_FLG_HIGH_PRIORITY, (PHOOK_GVA *)&pClkPage->SwapHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed for 0x%016llx: 0x%08x\n", va, status);
            goto cleanup_and_exit;
        }

        // Write hook. Needed on order to ensure correct EPT access rights are present.
        status = IntHookGvaSetHook(Cr3, va, hookLen, IG_EPT_HOOK_WRITE, IntMemClkHandleWrite,
                                   pClkPage, NULL, 0, (PHOOK_GVA *)&pClkPage->WriteHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed for 0x%016llx: 0x%08x\n", va, status);
            goto cleanup_and_exit;
        }

        // Read hook. On each read hitting our cloaked region, return the original date, thus hiding our modifications.
        status = IntHookGvaSetHook(Cr3, va, hookLen, IG_EPT_HOOK_READ, IntMemClkHandleRead,
                                   pClkPage, NULL, 0, (PHOOK_GVA *)&pClkPage->ReadHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed for 0x%016llx: 0x%08x\n", va, status);
            goto cleanup_and_exit;
        }

        va += hookLen;
    }

    if (0 != (Options & MEMCLOAK_OPT_APPLY_PATCH))
    {
        IntPauseVcpus();

        status = IntVirtMemWrite(VirtualAddress, Size, Cr3, pClkReg->PatchedData);

        IntResumeVcpus();

        if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status) &&
            (INT_STATUS_NO_MAPPING_STRUCTURES != status))
        {
            ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    *CloakHandle = pClkReg;

    return INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != pClkReg)
    {
        INTSTATUS status2 = IntMemClkUncloakRegionInternal(Options, pClkReg);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntMemClkUncloakRegionInternal failed: 0x%08x\n", status2);
        }
    }

    return status;
}


INTSTATUS
IntMemClkModifyOriginalData(
    _In_ void *CloakHandle,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _In_ void *Data
    )
///
/// @brief  Modifies the internal copy of the original data buffer held by a cloak region.
///
/// This will change the contents of the #MEMCLOAK_REGION.OriginalData buffer. This function will not enlarge or shrink
/// the buffer.
///
/// @param[in]  CloakHandle     The cloak handle. This is returned by #IntMemClkCloakRegion when a new cloak is set.
/// @param[in]  Offset          Offset inside the data buffer at which the change will be done.
/// @param[in]  Size            The size of the modified chunk.
/// @param[in]  Data            The new data.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 is CloakHandle is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 is Offset is outside the region's size.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Size (or the Size and Offset combination) make the write go
///             beyond the size of the region.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 is Data is NULL.
///
{
    PMEMCLOAK_REGION pClk;

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pClk = (PMEMCLOAK_REGION)CloakHandle;

    if (Offset >= pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (Offset + Size > pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Size > pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    memcpy(pClk->OriginalData + Offset, Data, Size);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntMemClkModifyPatchedData(
    _In_ void *CloakHandle,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _In_opt_ const void *Data
    )
///
/// @brief  Modifies the patched data inside the guest memory.
///
/// This will also change the contents of the #MEMCLOAK_REGION.PatchedData buffer. This function will not enlarge or
/// shrink the buffer. It will run with the VCPUs paused in order to ensure consistency of the patched data, as well
/// as the fact that no thread will start using the data while it is being modified. However, it will not check that
/// no guest threads are already inside the patched section. If this needs to be ensured the thread safeness mechanism
/// exposed by #IntThrSafeCheckThreads should be used before calling this function.
/// If the patched memory region is swapped out, the write inside the guest will not be possible. But in those cases,
/// the memory contents will be modified when the pages get swapped back in.
///
/// Whenever data that is hidden is modified, this function must be called. We must ensure permanent consistency
/// between the data in memory and the data inside the cloak structure, otherwise we may cause corruptions. We also
/// patch the data in memory ourselves, in order to avoid race conditions/sync issues.
///
///
/// @param[in]  CloakHandle     The cloak handle. This is returned by #IntMemClkCloakRegion when a new cloak is set.
/// @param[in]  Offset          Offset inside the data buffer at which the change will be done.
/// @param[in]  Size            The size of the modified chunk.
/// @param[in]  Data            The new data. If it is NULL, the buffer will be zeroed..
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 is CloakHandle is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 is Offset is outside the region's size.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Size (or the Size and Offset combination) make the write go
///             beyond the size of the region.
///
{
    INTSTATUS status;
    PMEMCLOAK_REGION pClk;

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pClk = (PMEMCLOAK_REGION)CloakHandle;

    if (Offset >= pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (Offset + Size > pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Size > pClk->Size)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    IntPauseVcpus();

    if (NULL != Data)
    {
        memcpy(pClk->PatchedData + Offset, Data, Size);
    }
    else
    {
        memset(pClk->PatchedData + Offset, 0, Size);
    }

    status = IntVirtMemWrite(pClk->Gva + Offset,
                             Size,
                             pClk->Cr3,
                             pClk->PatchedData + Offset);

    IntResumeVcpus();

    if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status) && (INT_STATUS_NO_MAPPING_STRUCTURES != status))
    {
        ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
        return status;
    }

    // Even if we couldn't modify the memory, because it's swapped out, we're still ok - on swap-in, the
    // original content will be brought back in memory.
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntMemClkUncloakRegionInternal(
    _In_ DWORD Options,
    _Inout_ PMEMCLOAK_REGION Region
    )
///
/// @brief  Removes a cloak region, making the original memory contents available again to the guest.
///
/// This function will undo any changes made to the cloaked memory region, as well as free any resources held by the
/// region. It will remove Region from the #gMemClkRegions list, will write the #MEMCLOAK_REGION.OriginalData buffer
/// back to the guest if the #MEMCLOAK_OPT_APPLY_PATCH option is used, will remove the EPT hooks set for the region
/// and will free the internal buffers.
/// Restoring the original contents of the memory is done with the VCPUs paused in order to ensure consistency of the
/// data as well as the fact that no thread will start using the data while it is being modified. However, it will not
/// check that no guest threads are already inside the patched section. If this needs to be ensured, the thread
/// safeness mechanism exposed by #IntThrSafeCheckThreads should be used before calling this function.
///
/// @param[in]      Options             Options that control the way accesses to the memory region are handled. Must be
///                                     0 or a combination of #MEMCLOAK_OPTIONS values.
/// @param[in, out] Region              The region to be removed. This pointer will no longer be valid after this
///                                     function returns.
///
/// @returns        #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    RemoveEntryList(&Region->Link);

    if (0 != (Options & MEMCLOAK_OPT_APPLY_PATCH))
    {
        IntPauseVcpus();

        memcpy(Region->PatchedData, Region->OriginalData, Region->Size);

        status = IntKernVirtMemWrite(Region->Gva, Region->Size, Region->OriginalData);

        IntResumeVcpus();

        if (!INT_SUCCESS(status) &&
            (INT_STATUS_PAGE_NOT_PRESENT != status) &&
            (INT_STATUS_NO_MAPPING_STRUCTURES != status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        }
    }

    for (DWORD i = 0; i < Region->PageCount; i++)
    {
        MEMCLOAK_PAGE *pPage = &Region->Pages[i];

        if (NULL != pPage->ReadHook)
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pPage->ReadHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }

        if (NULL != pPage->WriteHook)
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pPage->WriteHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }

        if (NULL != pPage->SwapHook)
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pPage->SwapHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }
    }

    IntMemClkCleanup(Region);

    return status;
}


INTSTATUS
IntMemClkUncloakRegion(
    _In_ void *CloakHandle,
    _In_ DWORD Options
    )
///
/// @brief  Removes a cloak region, making the original memory contents available again to the guest.
///
/// This is a thin wrapper over #IntMemClkUncloakRegionInternal that does some parameter validation..
///
/// @param[in]  CloakHandle         The handle of the cloaked region. This is obtained from #IntMemClkCloakRegion.
/// @param[in]  Options             Options that control the way accesses to the memory region are handled. Must be
///                                 0 or a combination of #MEMCLOAK_OPTIONS values.
///
/// @retval     #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if CloakHandle is NULL.
///
{
    INTSTATUS status;

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntMemClkUncloakRegionInternal(Options, CloakHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkUncloakRegionInternal failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntMemClkHashRegion(
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Size,
    _Out_ DWORD *Crc32
    )
///
/// @brief  Hashes the contents of a cloaked memory page.
///
/// The algorithm used for hashing is the one used by #Crc32ComputeFast.
///
/// @param[in]  VirtualAddress  The virtual address of the start of the region..
/// @param[in]  PhysicalAddress The physical address to which VirtualAddress translates to.
/// @param[in]  Size            The size of the hashed buffer. This must not be larger than #PAGE_SIZE.
/// @param[out] Crc32           The crc32 of the hashed region.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 is the hashed region crosses a page boundary.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 is Crc32 is NULL.
///
{
    INTSTATUS status;
    QWORD virtPage;
    LIST_ENTRY *list;
    DWORD pageOffset, intOffset, size;
    static BYTE pPageContent[PAGE_SIZE];

    if ((VirtualAddress & PAGE_OFFSET) + Size > PAGE_SIZE)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Crc32)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    virtPage = VirtualAddress & PAGE_MASK;

    status = IntPhysicalMemRead(PhysicalAddress & PHYS_PAGE_MASK, PAGE_SIZE, pPageContent, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysMemRead failed: 0x%08x\n", status);
        return status;
    }

    list = gMemClkRegions.Flink;
    while (list != &gMemClkRegions)
    {
        PMEMCLOAK_REGION pReg = CONTAINING_RECORD(list, MEMCLOAK_REGION, Link);

        list = list->Flink;

        if ((pReg->Gva >= virtPage) && (pReg->Gva < virtPage + PAGE_SIZE))
        {
            // The cloaked region is contained within the page or starts within this page.
            pageOffset = pReg->Gva & PAGE_OFFSET;
            intOffset = 0;
            size = MIN(PAGE_SIZE - pageOffset, pReg->Size);
        }
        else if ((virtPage >= pReg->Gva) && (virtPage < pReg->Gva + pReg->Size))
        {
            // The cloaked region contains the page or parts of the page.
            pageOffset = 0;
            intOffset = (DWORD)(virtPage - pReg->Gva);
            size = MIN(PAGE_SIZE, pReg->Size - intOffset);
        }
        else
        {
            // No overlap, continue.
            continue;
        }

        memcpy(&pPageContent[pageOffset], &pReg->OriginalData[intOffset], size);
    }

    *Crc32 = Crc32ComputeFast(&pPageContent[VirtualAddress & PAGE_OFFSET], Size, 0);

    return status;

}


BOOLEAN
IntMemClkIsPtrInCloak(
    _In_ const void *Cloak,
    _In_ QWORD Ptr
    )
///
/// @brief  Checks if a guest virtual address is located inside a cloak region.
///
/// @param[in]  Cloak   The cloak handle. This is obtained from #IntMemClkCloakRegion
/// @param[in]  Ptr     The guest virtual address to be checked.
///
/// @retval     True if Ptr is inside the cloak region
/// @retval     False if Ptr is not inside the cloak region or if Cloak is NULL.
///
{
    const MEMCLOAK_REGION *pReg;

    if (NULL == Cloak)
    {
        return FALSE;
    }

    pReg = Cloak;
    if (Ptr >= pReg->Gva && Ptr < pReg->Gva + pReg->Size)
    {
        return TRUE;
    }

    return FALSE;
}


INTSTATUS
IntMemClkGetOriginalData(
    _In_ void *CloakHandle,
    _Out_ BYTE **OriginalData,
    _Out_  DWORD *Length
    )
///
/// @brief  Returns the original data of a cloaked region.
///
/// This will return a pointer to the internal #MEMCLOAK_REGION.OriginalData buffer.
///
/// @param[in]  CloakHandle     The cloak handle. This is obtained from #IntMemClkCloakRegion.
/// @param[out] OriginalData    Pointer to a BYTE* that will receive the address of the original data buffer.
/// @param[out] Length          Pointer to a DWORD that will receive the size of the original data buffer.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if CloakHandle is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if OriginalData is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Length is NULL.
///
{
    MEMCLOAK_REGION *pClk;

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == OriginalData)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pClk = (MEMCLOAK_REGION *)CloakHandle;

    *OriginalData = pClk->OriginalData;

    *Length = pClk->Size;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntMemClkUnInit(
    void
    )
///
/// @brief  Uninits the memory cloak subsystem.
///
/// This is used when introcore unloads and free any internal resources as well as check if there are still cloak
/// regions set. During a normal unload process, when this function is called, there should be no remaining regions
/// set, as whoever sets them is responsible of undoing any changes it has done. However, in that case the remaining
/// regions will be uncloaked, but that may leave the guest in an unstable guest and no other subsystem should depend
/// on this behavior.
///
/// @retval     #INT_STATUS_SUCCESS always.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = gMemClkRegions.Flink;
    while (list != &gMemClkRegions)
    {
        PMEMCLOAK_REGION pClkReg = CONTAINING_RECORD(list, MEMCLOAK_REGION, Link);
        list = list->Flink;

        ERROR("[ERROR] There should be no memcloaks remaining... Got one on %llx, %llx, %d!\n",
              pClkReg->Gva, pClkReg->Cr3, pClkReg->Size);

        if (pClkReg->OriginalData)
        {
            IntDumpBuffer(pClkReg->OriginalData, 0, pClkReg->Size, 16, 1, TRUE, FALSE);
        }

        if (pClkReg->PatchedData)
        {
            IntDumpBuffer(pClkReg->PatchedData, 0, pClkReg->Size, 16, 1, TRUE, FALSE);
        }

        status = IntMemClkUncloakRegionInternal(0, pClkReg);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkUncloakRegionInternal failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


void
IntMemClkDump(
    void
    )
///
/// @brief  Dumps all the active cloak regions.
///
{
    if (IsListEmpty(&gMemClkRegions))
    {
        LOG("No cloack regions!\n");
    }

    for (LIST_ENTRY *entry = gMemClkRegions.Flink; entry != &gMemClkRegions; entry = entry->Flink)
    {
        PMEMCLOAK_REGION pClkReg = CONTAINING_RECORD(entry, MEMCLOAK_REGION, Link);

        LOG("Region @ [0x%016llx, 0x%016llx) with Cr3 = 0x%016llx. Page count: %d. Options: 0x%08x\n",
            pClkReg->Gva, pClkReg->Gva + pClkReg->Size,
            pClkReg->Cr3, pClkReg->PageCount, pClkReg->Options);
        LOG("Original data:\n");
        IntDumpBuffer(pClkReg->OriginalData, pClkReg->Gva, pClkReg->Size, 16, 1, TRUE, TRUE);
        LOG("Patched data:\n");
        IntDumpBuffer(pClkReg->PatchedData, pClkReg->Gva, pClkReg->Size, 16, 1, TRUE, TRUE);

        for (DWORD i = 0; i < pClkReg->PageCount; i++)
        {
            PMEMCLOAK_PAGE pClkPage = &pClkReg->Pages[i];

            NLOG("\t\tData offset: 0x%08x Start: 0x%08x End: 0x%08x\n",
                 pClkPage->DataOffset, pClkPage->PageStartOffset, pClkPage->PageEndOffset);
        }
    }
}

/// @}
