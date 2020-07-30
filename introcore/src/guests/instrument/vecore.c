/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vecore.h"
#include "winagent.h"
#include "alerts.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"
#include "kernvm.h"
#include "loader.h"
#include "memcloak.h"
#include "winagent_ve_x64.h"
#include "winapi.h"
#include "winpe.h"
#include "winpower.h"
#include "ptfilter.h"

///
/// @file vecore.c
///
/// @brief Handles the introspection part of the VE agent injection and handling.
///
/// This module deals with VE agent injection and handling. The main role is to inject and remove the agent from the
/// guest memory. VE works by marking all hooked page-table pages as convertible - this means that instead of an
/// EPT violation, the CPU would generate an in-guest exception when triggering an EPT fault on them. The in-guest
/// exception is delivered much faster (no need for extensive state save/restore like VM exit/VM entry). In addition,
/// the in-guest agent runs in the context of the faulting process, so there is no need to do slow memory map/unmap
/// operations, as the memory can be directly accessed. Emulating page-table accesses is also very fast, since we
/// don't have to map/unmap memory. The main logical steps done by this module are:
/// 1. On initialization, determine whether the HV supports VE and VMFUNC; If support is not found, VE will not
/// be used.
/// 2. Create a new, alternate EPT, called the protected EPT, where the agent will run when a VE takes place;
/// 3. Inject the VE agent, when needed;
/// 4. Remove the VE agent, when needed.
/// Additional details can be found in each individual function:
/// 1. For agent injection & initialization, please check out #IntVeDeliverDriverForLoad;
/// 2. For agent removal, please check out #IntVeDeliverDriverForUnload.
///
/// Important design decisions
/// 1. The VE handler is hooked using an inline code hook inside the OS KiVirtualizatonExceptionHandler.
/// The reason behind this decision is PatchGuard: normally hooking the VE handler inside the IDT would trigger
/// PatchGuard bug-checks. In order to hide the hook, complicated steps must be taken:
/// - Relocate each IDT inside a new page, where the VE handler will be hooked;
/// - Read-hook the original IDT, in order to return the unmodified contents to PatchGuard;
/// - Intercept SIDT, in order to show PatchGuard the old IDT;
/// - Read-hooking the active IDT (pointed by IDTR) is impossible, as each interrupt delivery will trigger a fault.
/// 2. We rely on the OS memory-manager to maintain non-paged memory pages accessed and/or dirty.
/// The reason behind this is that during the delivery of another fault, a VE may be generated, which will make
/// the VE handler execute with potentially wrong GS base or even user-mode stack (in case of SYSCALLs). The correct
/// approach is to make the VE handler use IST (like NMI or DF handlers), but again, this is impossible to do because
/// the TSS would also have to be modified, and the modifications hidden from potential PatchGuard reads.
/// Another approach would be to enforce A/D bits always present using the EPT, but this would involve multiple
/// hooks to be placed on memory pages which are otherwise not monitored:
/// - The Processor Control Regions of each VCPU;
/// - The memory pages containing entry-points for every IDT entry and the SYSCALL;
/// - The regular kernel stack;
/// - Every IST kernel stack;
/// - The IDTs, as it could potentially be accessed during the delivery of another event;
/// - The GDTs, as it could potentially be accessed during segmentation related operations;
/// - The TSSs, as it could potentially be accessed during an IST lookup.
/// In addition, there are two cases where the A/D must be enforced: whenever the a PTE is modified, and during
/// initialization. However, in both of these cases, enforcing A/D bit without the OS knowing/wanting may lead
/// to other problems (such as memory management bug checks). Instead, we simply leverage the OS itself.
/// Since Windows does not clear the A/D bits for non-paged areas, and since an attacker cannot do this from
/// user-mode, we consider that this is not an avenue for normal privilege escalation, as an A/D VE can't take
/// place in sensitive points during normal execution. These pages are always mapped A/D and remain so.
/// The best approach would be to contact Microsoft and nicely ask them to make their VE handler right.
/// 3. There are two EPT views: the untrusted EPT view (in which the guest normally runs) and the protected EPT view
/// (in which the agent runs). When a VE takes place, the agent trampoline code will use the VMFUNC instruction
/// to switch into the protected view. When leaving the agent, VMFUNC is used again to switch into the previous
/// EPT view. These two EPT views have different access rights:
/// - Inside the untrusted EPT view, all normal HVI protections are set; in addition, the VE agent is protected:
/// all pages belonging to the agent, except for the trampoline page, are marked no-access, so the guest cannot
/// read, write or execute agent pages;
/// - Inside the trusted EPT view, the agent has normal restrictions (data pages read/write, code pages read/execute),
/// but the rest of the guest is mapped read/write only - no execute rights means no code can be arbitrary executed
/// inside the agent;
/// - The agent pages can be occasionally remapped by the OS; due to this, we handle internally such remappings
/// by moving the contents of the old VE agent page into the new VE agent page; we can't let the OS do this, as a
/// VE can be triggered during normal remapping operation, which could modify the remapped page itself, thus out-dating
/// the freshly copied content.
/// 4. The VE optimization works only on Windows x64. It seems that the largest page-table related performance
/// overhead is generated on 64 bit Windows. This can be explained by the larger virtual-address spaces and higher
/// number of page-tables.
/// 5. VE agent initialization is done entirely by Introcore. There are no in-guest initialization steps, so from
/// the guest perspective, the agent appears and disappears atomically. This removes potential security implications
/// such as guest tampering with the agent before initialization is finished.
///


#define VE_DRV_NAME         u"#VE Agent"
#define VE_DRV_PATH         VE_DRV_NAME

/// Indicate the \#VE agent state.
static KERNEL_DRIVER gVeModule;

BOOLEAN gVePendingDeploy, gVeDeployed, gVePendingUnload, gVeVeInitialized, gVeLoadFailed;

QWORD gVeDriverAddress;         ///< The guest virtual address where the driver was deployed.
DWORD gVeDriverSize;            ///< The driver virtual size.
DWORD gVeDriverEntryPoint;      ///< The driver entry point (RVA).
PBYTE gVeLoadedImageBuffer;     ///< Contains the loaded \#VE module, relocated and such.
QWORD gVeInfoPages;             ///< Guest virtual address where the VE info pages are located.

void *gVeHookObject;            ///< Hook object containing VE agent protection in the untrusted EPT.
void *gVeHandlerCloak;          ///< Cloak handle used to hide the guest VE handler.
void **gVeDriverPages;          ///< Swap hook handle for each VE driver page.
QWORD gVeMaxGpa;                ///< Maximum GPA accessible to the guest.
QWORD gVeCache;                 ///< The VE page-table cache.



///
/// Describes one VE cache page.
///
struct
{
    VE_CACHE_LINE   *Page;      ///< Mapped page inside Introspection virtual address space.
    DWORD           Indexes[VE_CACHE_BUCKETS]; ///< Array of used indexes inside the cache page.
} gVeCachePages[VE_CACHE_LINES];


static INTSTATUS
IntVeFindKernelKvaShadowAndKernelExit(
    _Inout_ QWORD *KiKernelExit
    );

static INTSTATUS
IntVeSetVeInfoPage(
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoPageGva
    );

static void
IntVeResetState(
    void
    );

#define VE_TRAMPO_SIZE      24



static void
IntVeDumpVeInfoPage(
    _In_ DWORD CpuNumber
    )
///
/// @brief Dump the VE info page on the provided VCPU.
///
/// @param[in]  CpuNumber   The VCPU number to dump the VE info page from.
///
{
    INSTRUX ix;
    PVCPU_STATE vcpu = &gGuest.VcpuArray[CpuNumber];
    QWORD veInfoGpa;
    BOOLEAN c;
    VA_TRANSLATION tr;
    CHAR text[ND_MIN_BUF_SIZE];

    if (vcpu->VeInfoPage == NULL)
    {
        LOG("NO #VE info page on CPU %d!\n", CpuNumber);
        return;
    }

    LOG("**** #VE info page on CPU %d\n", vcpu->Index);
    LOG("    Reason = 0x%08x, Reserved = 0x%08x, Qualification = 0x%016llx\n",
        vcpu->VeInfoPage->Reason, vcpu->VeInfoPage->Reserved, vcpu->VeInfoPage->Qualification);
    LOG("    GLA = 0x%016llx, GPA = 0x%016llx, EPT = 0x%016llx, Reserved = 0x%016llx\n",
        vcpu->VeInfoPage->GuestLinearAddress, vcpu->VeInfoPage->GuestPhysicalAddress,
        vcpu->VeInfoPage->EptpIndex, vcpu->VeInfoPage->Reserved2);
    LOG("    RAX = 0x%016llx RCX = 0x%016llx RDX = 0x%016llx RBX = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.RAX, vcpu->VeInfoPage->Registers.RCX,
        vcpu->VeInfoPage->Registers.RDX, vcpu->VeInfoPage->Registers.RBX);
    LOG("    RSP = 0x%016llx RBP = 0x%016llx RSI = 0x%016llx RDI = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.RSP, vcpu->VeInfoPage->Registers.RBP,
        vcpu->VeInfoPage->Registers.RSI, vcpu->VeInfoPage->Registers.RDI);
    LOG("    R8  = 0x%016llx R9  = 0x%016llx R10 = 0x%016llx R11 = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.R8, vcpu->VeInfoPage->Registers.R9,
        vcpu->VeInfoPage->Registers.R10, vcpu->VeInfoPage->Registers.R11);
    LOG("    R12 = 0x%016llx R13 = 0x%016llx R14 = 0x%016llx R15 = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.R12, vcpu->VeInfoPage->Registers.R13,
        vcpu->VeInfoPage->Registers.R14, vcpu->VeInfoPage->Registers.R15);
    LOG("    RIP = 0x%016llx FLG = 0x%016llx CS = 0x%016llx SS = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.RIP, vcpu->VeInfoPage->Registers.RFLAGS,
        vcpu->VeInfoPage->Registers.CS, vcpu->VeInfoPage->Registers.SS);
    LOG("    CR0 = 0x%016llx CR3 = 0x%016llx CR4 = 0x%016llx DR7 = 0x%016llx\n",
        vcpu->VeInfoPage->Registers.CR0, vcpu->VeInfoPage->Registers.CR3,
        vcpu->VeInfoPage->Registers.CR4, vcpu->VeInfoPage->Registers.DR7);
    LOG("    OLD = 0x%016llx NEW = 0x%016llx RSPN = %p RSPO = %p\n",
        vcpu->VeInfoPage->OldValue, vcpu->VeInfoPage->NewValue, vcpu->VeInfoPage->ProtectedStack,
        vcpu->VeInfoPage->OriginalStack);

    IntDecDecodeInstructionFromBuffer(vcpu->VeInfoPage->Instruction, 16, IG_CS_TYPE_64B, &ix);

    LOG("**** Instruction stream:\n");
    IntDisasmGva(vcpu->VeInfoPage->Registers.RIP, 0x100);

    LOG("**** Instruction in cache:\n");
    NdToText(&ix, vcpu->VeInfoPage->Registers.RIP, ND_MIN_BUF_SIZE, text);
    LOG("0x%016llx -> %s\n", vcpu->VeInfoPage->Registers.RIP, text);

    LOG("**** VE core state:\n");

    IntTranslateVirtualAddress(vcpu->VeInfoPage->Self, gGuest.Mm.SystemCr3, &veInfoGpa);
    IntTranslateVirtualAddressEx(vcpu->VeInfoPage->GuestLinearAddress, vcpu->VeInfoPage->Registers.CR3, 0, &tr);

    LOG("*** Translation for GLA 0x%016llx\n", vcpu->VeInfoPage->GuestLinearAddress);
    LOG("CR3   = 0x%016llx", vcpu->VeInfoPage->Registers.CR3);
    LOG("PML4e = 0x%016llx", tr.MappingsEntries[0]);
    LOG("PDPe  = 0x%016llx", tr.MappingsEntries[1]);
    LOG("PDe   = 0x%016llx", tr.MappingsEntries[2]);
    LOG("PTe   = 0x%016llx", tr.MappingsEntries[3]);

    LOG("Self at 0x%016llx, phys at 0x%016llx, CPU %lld, current %d\n", vcpu->VeInfoPage->Self, veInfoGpa,
        vcpu->VeInfoPage->Index, CpuNumber);

    IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, vcpu->VeInfoPage->GuestPhysicalAddress, &c);
    LOG("The faulted GPA 0x%016llx is %s!\n", vcpu->VeInfoPage->GuestPhysicalAddress,
        c ? "convertible" : "NOT CONVERTIBLE");

    IntGetGprs(CpuNumber, &gGuest.VcpuArray[CpuNumber].Regs);
    IntDumpArchRegs(&gGuest.VcpuArray[CpuNumber].Regs);
    LOG("RFLAGS = 0x%016llx\n", gGuest.VcpuArray[CpuNumber].Regs.Flags);
    IntDisasmGva(gGuest.VcpuArray[CpuNumber].Regs.Rip, 0x100);

    LOG("==============================================================================================\n");
}


INTSTATUS
IntVeHandleEPTViolationInProtectedView(
    _In_ IG_EPT_ACCESS AccessType,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle an EPT violation inside the protected EPT view.
///
/// This function is called from the main EPT violation handler whenever a violation takes place inside the protected
/// EPT view. We only dump as much info as we can & we generate an alert, after which we re-enter the guest. Normally,
/// this will lead to a hang, as the guest would keep generating such EPT violations, but this is expected, as only
/// a bug or an attack may end up generating such a violation.
///
/// @param[in]  AccessType  Access type. Can be a combination of #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE and
///                         #IG_EPT_HOOK_EXECUTE.
/// @param[out] Action      Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    PIG_ARCH_REGS regs = NULL;
    INTRO_ACTION_REASON reason;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    PEVENT_EPT_VIOLATION pEptViol = &gAlert.Ept;
    DWORD zoneFlags;
    VA_TRANSLATION tr = { 0 };
    BYTE r1, w1, x1, r2, w2, x2;
    BOOLEAN c1, c2;
    DWORD eptindex;

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));
    memzero(pEptViol, sizeof(*pEptViol));

    LOG("[VECORE] %s took place inside the #VE agent in protected view at GLA 0x%llx, from RIP 0x%llx!\n",
        IG_EPT_HOOK_READ == AccessType ? "Read" :
        IG_EPT_HOOK_WRITE == AccessType ? "Write" :
        (IG_EPT_HOOK_READ | IG_EPT_HOOK_WRITE) == AccessType ? "Read-Write" :
        IG_EPT_HOOK_EXECUTE == AccessType ? "Execute" : "-",
        gVcpu->Gla,
        gVcpu->Regs.Rip);

    // The following code is used for debugging, so it should be left here for now. It helped us pinpoint a nasty race
    // condition.
    IntGetCurrentEptIndex(IG_CURRENT_VCPU, &eptindex);
    LOG("[VECORE] Current VCPU is %d\n", gVcpu->Index);
    LOG("[VECORE] System CR3 = 0x%016llx, Current CR3 = 0x%016llx\n", gGuest.Mm.SystemCr3, gVcpu->Regs.Cr3);
    LOG("[VECORE] Current EPT = %d, untrusted EPT = %d, protected EPT = %d\n", eptindex, gGuest.UntrustedEptIndex,
        gGuest.ProtectedEptIndex);

    IntTranslateVirtualAddressEx(gVcpu->Regs.Rip, gVcpu->Regs.Cr3, 0, &tr);
    IntGetEPTPageProtection(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &r1, &w1, &x1);
    IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &c1);
    IntGetEPTPageProtection(gGuest.ProtectedEptIndex, tr.PhysicalAddress, &r2, &w2, &x2);
    IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &c2);
    LOG("[VECORE] RIP GLA 0X%016llx, GPA 0x%016llx, EPT untrusted %c%c%c/%c, EPT protected %c%c%c/%c\n",
        gVcpu->Regs.Rip, tr.PhysicalAddress, r1 ? 'R' : '-', w1 ? 'W' : '-', x1 ? 'X' : '-', c1 ? 'C' : '-',
        r2 ? 'R' : '-', w2 ? 'W' : '-', x2 ? 'X' : '-', c2 ? 'C' : '-');

    IntTranslateVirtualAddressEx(gVcpu->Gla, gVcpu->Regs.Cr3, 0, &tr);
    IntGetEPTPageProtection(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &r1, &w1, &x1);
    IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &c1);
    IntGetEPTPageProtection(gGuest.ProtectedEptIndex, tr.PhysicalAddress, &r2, &w2, &x2);
    IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &c2);
    LOG("[VECORE] GVA GLA 0X%016llx, GPA 0x%016llx, EPT untrusted %c%c%c/%c, EPT protected %c%c%c/%c\n",
        gVcpu->Gla, tr.PhysicalAddress, r1 ? 'R' : '-', w1 ? 'W' : '-', x1 ? 'X' : '-', c1 ? 'C' : '-',
        r2 ? 'R' : '-', w2 ? 'W' : '-', x2 ? 'X' : '-', c2 ? 'C' : '-');

    IntDumpArchRegs(&gVcpu->Regs);
    IntVeDumpVeInfoPages();

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    if (IG_EPT_HOOK_EXECUTE == AccessType)
    {
        zoneFlags = ZONE_EXECUTE;
    }
    else if (!!(IG_EPT_HOOK_WRITE & AccessType))
    {
        zoneFlags = ZONE_WRITE;
    }
    else if (!!(IG_EPT_HOOK_READ & AccessType))
    {
        zoneFlags = ZONE_READ;
    }
    else
    {
        ERROR("[ERROR] Invalid access type!");
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    STATS_ENTER(statsExceptionsKern);
    status = IntExceptGetVictimEpt(&gVeModule,
                                   gVcpu->Gpa,
                                   gVcpu->Gla,
                                   introObjectTypeVeAgent,
                                   zoneFlags,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed: 0x%08x\n", status);
        reason = introReasonInternalError;
    }
    else
    {
        status = IntExceptKernelGetOriginator(&originator, 0);
        if (INT_STATUS_EXCEPTION_BLOCK == status)
        {
            reason = introReasonNoException;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptKernelGetOriginator failed: 0x%08x\n", status);
            reason = introReasonInternalError;
        }
    }

    IntExceptKernelLogInformation(&victim, &originator, *Action, reason);

    STATS_EXIT(statsExceptionsKern);

    regs = &gVcpu->Regs;

    if (IG_EPT_HOOK_EXECUTE == AccessType)
    {
        IntDisasmGva(victim.Ept.Gva, PAGE_SIZE - (victim.Ept.Gva & PAGE_OFFSET));
        IntDumpArchRegs(regs);
    }

    pEptViol->Header.Action = *Action;
    pEptViol->Header.Reason = reason;
    pEptViol->Header.MitreID = idRootkit;

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);
    IntAlertEptFillFromKmOriginator(&originator, pEptViol);
    IntAlertEptFillFromVictimZone(&victim, pEptViol);

    pEptViol->Header.Flags = IntAlertCoreGetFlags(0, reason);
    pEptViol->Header.Flags |= ALERT_FLAG_PROTECTED_VIEW;
    if (gGuest.KernelBetaDetections)
    {
        pEptViol->Header.Flags |= ALERT_FLAG_BETA;
    }

    IntAlertFillWinProcessByCr3(regs->Cr3, &pEptViol->Header.CurrentProcess);
    IntAlertFillCodeBlocks(originator.Original.Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
    IntAlertFillExecContext(0, &pEptViol->ExecContext);
    IntAlertFillVersionInfo(&pEptViol->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeHandleAccess(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle accesses inside the VE agent (outside the protected view).
///
/// This function handles all invalid accesses inside the VE agent. By default, we block them all.
///
/// @param[in]  Context     Unused.
/// @param[in]  Hook        The GPA hook handle. Unused.
/// @param[in]  Address     The accessed address.
/// @param[in]  Action      Desired action. By default, this is #introGuestNotAllowed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    PEVENT_EPT_VIOLATION pEptViol = &gAlert.Ept;
    PIG_ARCH_REGS regs = NULL;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTRO_ACTION_REASON reason;
    DWORD zoneFlags;
    BYTE accessType;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);

    accessType = ((PHOOK_GPA)Hook)->Header.EptHookType;

    if (IG_EPT_HOOK_EXECUTE == accessType)
    {
        zoneFlags = ZONE_EXECUTE;
    }
    else if (IG_EPT_HOOK_WRITE == accessType)
    {
        zoneFlags = ZONE_WRITE;
    }
    else if (IG_EPT_HOOK_READ == accessType)
    {
        // IMPORTANT: We occasionally get some random reads from the \#VE agent, triggered by the nt
        // (memcpy & friends), which are called from hal DMA related APIs. In order to avoid alert spams,
        // we will simply block these reads, and send an alert only for debug builds. There is no point in sending
        // alerts for reads from the \#VE agent, since this wouldn't be considered a legit attack (more like some
        // targeted attack, but there are no secrets inside the \#VE agent, and an attacker could get its hands on the
        // \#VE binary anyway).
        // NOTE: since we support \#VE agent pages remapping, there's no point in sending any alerts for reads. We will
        // simply silently block reads and do the remapping.
        *Action = introGuestNotAllowed;
        return INT_STATUS_SUCCESS;
    }
    else
    {
        ERROR("[ERROR] Invalid access type!");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    LOG("[VECORE] %s took place inside the #VE agent at GLA 0x%llx, from RIP 0x%llx!\n",
        ZONE_READ == zoneFlags ? "Read" :
        (ZONE_WRITE == zoneFlags ? "Write" :
         (ZONE_EXECUTE == zoneFlags ? "Execute" : "-")),
        gVcpu->Gla,
        gVcpu->Regs.Rip);


    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));
    memzero(pEptViol, sizeof(*pEptViol));

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptGetVictimEpt(&gVeModule,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeVeAgent,
                                   zoneFlags,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed: 0x%08x\n", status);
        reason = introReasonInternalError;
    }
    else
    {
        status = IntExceptKernelGetOriginator(&originator, 0);
        if (INT_STATUS_EXCEPTION_BLOCK == status)
        {
            reason = introReasonNoException;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptKernelGetOriginator failed: 0x%08x\n", status);
            reason = introReasonInternalError;
        }
    }

    IntExceptKernelLogInformation(&victim, &originator, *Action, reason);

    STATS_EXIT(statsExceptionsKern);

    regs = &gVcpu->Regs;

    if (IG_EPT_HOOK_EXECUTE == accessType)
    {
        IntDisasmGva(victim.Ept.Gva, PAGE_SIZE - (victim.Ept.Gva & PAGE_OFFSET));
        IntDumpArchRegs(regs);
    }

    pEptViol->Header.Action = *Action;
    pEptViol->Header.Reason = reason;
    pEptViol->Header.MitreID = idRootkit;

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(&originator, pEptViol);
    IntAlertEptFillFromVictimZone(&victim, pEptViol);

    pEptViol->Header.Flags |= IntAlertCoreGetFlags(0, reason);
    if (gGuest.KernelBetaDetections)
    {
        pEptViol->Header.Flags |= ALERT_FLAG_BETA;
    }

    IntAlertFillWinProcessByCr3(regs->Cr3, &pEptViol->Header.CurrentProcess);

    IntAlertFillCodeBlocks(originator.Original.Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
    IntAlertFillExecContext(0, &pEptViol->ExecContext);

    IntAlertFillVersionInfo(&pEptViol->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeHandleSwap(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief Handle VE agent page remapping.
///
/// This function handles remapping operations that take place on the agent memory. This is a very sensitive operation,
/// as the guest OS may have already copied the contents of the old page into the new page, but by triggering a VE
/// inside the guest, the contents of that page may have modified. Therefore, we must make sure that we do another copy
/// of that page, with the VCPUs paused (in order to make sure no other VCPU touches that page), and then write the
/// new page-table entry ourselves. In addition, this function takes care of moving the EPT page protection from the
/// old page to the new page (in both the untrusted and protected EPT views), and it handles remapping other VE cache
/// pages and of the VE info pages as well.
///
/// @param[in]  Context         Unused.
/// @param[in]  VirtualAddress  The swapped guest virtual address, belonging to the VE agent.
/// @param[in]  OldEntry        Old page-table entry.
/// @param[in]  NewEntry        New page-table entry.
/// @param[in]  OldPageSize     Old page size. Unused.
/// @param[in]  NewPageSize     New page size. Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PBYTE oldPage, newPage;
    QWORD oldAddr, newAddr;
    BYTE r, w, x;

    oldPage = newPage = NULL;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(OldPageSize);
    UNREFERENCED_PARAMETER(NewPageSize);

    LOG("[VECORE] Modified #VE agent page 0x%016llx from 0x%016llx to 0x%016llx!\n",
        VirtualAddress,
        OldEntry,
        NewEntry);

    // The pages are the same, so we can safely bail out here.
    if ((OldPageSize == NewPageSize) && !!(OldEntry & PT_P) && !!(NewEntry & PT_P) &&
        CLEAN_PHYS_ADDRESS64(OldEntry) == CLEAN_PHYS_ADDRESS64(NewEntry))
    {
        return INT_STATUS_SUCCESS;
    }

    if (!(OldEntry & PT_P) || !(NewEntry & PT_P))
    {
        ERROR("[ERROR] Old or new PT entry is not valid!\n");
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
    }


    oldAddr = (CLEAN_PHYS_ADDRESS64(OldEntry) & ~(OldPageSize - 1)) + (VirtualAddress & (OldPageSize - 1));
    newAddr = (CLEAN_PHYS_ADDRESS64(NewEntry) & ~(NewPageSize - 1)) + (VirtualAddress & (NewPageSize - 1));


    // 1. Copy the contents of the old page into the new page.

    // Map the old page.
    status = IntPhysMemMap(oldAddr, PAGE_SIZE, 0, &oldPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping the old address: 0x%08x\n", status);
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
        goto cleanup_and_exit;
    }

    // Map the new page.
    status = IntPhysMemMap(newAddr, PAGE_SIZE, 0, &newPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping the old address: 0x%08x\n", status);
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
        goto cleanup_and_exit;
    }

    // Copy the contents.
    memcpy(newPage, oldPage, PAGE_SIZE);


    // 2. Update the EPT access rights for the old & new pages inside the protected view.

    // Update the access rights for these new GPAs inside the protected view.
    status = IntGetEPTPageProtection(gGuest.ProtectedEptIndex, oldAddr, &r, &w, &x);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetEPTPageProtection failed: 0x%08x\n", status);
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
    }

    // Mark the old page as RW- inside the protected view.
    status = IntSetEPTPageProtection(gGuest.ProtectedEptIndex, oldAddr, 1, 1, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetEPTPageProtection failed: 0x%08x\n", status);
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
    }

    // Put the required access rights into the new page now.
    status = IntSetEPTPageProtection(gGuest.ProtectedEptIndex, newAddr, r, w, x);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetEPTPageProtection failed: 0x%08x\n", status);
        IntVeDumpVeInfoPages();
        IntEnterDebugger();
    }

    // 3. Move the protection to the new page - this is handled by the hook_gva swap callback. Note that the VCPUs
    // will remain paused for ALL the swap callbacks as long as there is at least one high priority callback such as
    // this one, so atomicity is ensured.

    // 4. Handle #VE cache remapping - we must unmap the old page and remap it to the new location.
    for (QWORD i = 0; i < VE_CACHE_LINES; i++)
    {
        if (gVeCache + PAGE_SIZE * i == VirtualAddress)
        {
            LOG("[VECORE] Remapping the #VE cache page at index %llu\n", i);

            if (NULL != gVeCachePages[i].Page)
            {
                IntVirtMemUnmap(&gVeCachePages[i].Page);
            }

            break;
        }
    }

    // 5. Handle #VE info page remapping by updating it inside the VMCS.

    // If a #VE info page is being remapped, make sure we update it inside the VMCS.
    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        if (gVeInfoPages + PAGE_SIZE * (QWORD)i == VirtualAddress)
        {
            LOG("[VECORE] Remapping the #VE info page for VCPU %d\n", i);

            // A #VE info page is being remapped, update the VMCS.
            status = IntVeSetVeInfoPage(i, VirtualAddress);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVeSetVeInfoPage failed: 0x%08x\n", status);
                IntVeDumpVeInfoPages();
                IntEnterDebugger();
            }

            break;
        }
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != newPage)
    {
        IntPhysMemUnmap(&newPage);
    }

    if (NULL != oldPage)
    {
        IntPhysMemUnmap(&oldPage);
    }

    return status;
}


static INTSTATUS
IntVeHookVeDriver(
    void
    )
///
/// @brief Protect the VE driver inside the untrusted EPT view.
///
/// This function will hook the VE driver inside the regular, default, untrusted EPT view. All sections
/// will be hooked against reads & writes, and all the sections, except for the VMFUNC trampoline
/// (section VESTUB) will be hooked against executions as well.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER if the VE image was not loaded.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD i = 0;
    PIMAGE_SECTION_HEADER pSec = NULL;
    DWORD sectionRva = 0;
    DWORD sectionCount = 0;

    if (NULL == gVeLoadedImageBuffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntPeListSectionsHeaders(0, gVeLoadedImageBuffer, gVeDriverSize, &sectionRva, &sectionCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeIterateSections failed with status: 0x%08x\n", status);
        return status;
    }

    LOG("[VECORE] Hooking headers against any access...\n");

    status = IntHookObjectHookRegion(gVeHookObject,
                                     gGuest.Mm.SystemCr3,
                                     gVeDriverAddress,
                                     PAGE_SIZE,
                                     IG_EPT_HOOK_WRITE,
                                     IntVeHandleAccess,
                                     NULL, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
    }

    status = IntHookObjectHookRegion(gVeHookObject,
                                     gGuest.Mm.SystemCr3,
                                     gVeDriverAddress,
                                     PAGE_SIZE,
                                     IG_EPT_HOOK_READ,
                                     IntVeHandleAccess,
                                     NULL, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
    }

    status = IntHookObjectHookRegion(gVeHookObject,
                                     gGuest.Mm.SystemCr3,
                                     gVeDriverAddress,
                                     PAGE_SIZE,
                                     IG_EPT_HOOK_EXECUTE,
                                     IntVeHandleAccess,
                                     NULL, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
    }

    pSec = (IMAGE_SECTION_HEADER *)(gVeLoadedImageBuffer + sectionRva);
    for (i = 0; i < sectionCount; i++, pSec++)
    {
        LOG("[VECORE] Hooking section %d (%s) with characteristics 0x%08x against writes\n",
            i, pSec->Name, pSec->Characteristics);

        status = IntHookObjectHookRegion(gVeHookObject,
                                         gGuest.Mm.SystemCr3,
                                         pSec->VirtualAddress + gVeDriverAddress,
                                         ROUND_UP((QWORD)pSec->Misc.VirtualSize, PAGE_SIZE),
                                         IG_EPT_HOOK_WRITE,
                                         IntVeHandleAccess,
                                         NULL, 0, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
        }

        LOG("[VECORE] Hooking section %d (%s) with characteristics 0x%08x against reads\n",
            i, pSec->Name, pSec->Characteristics);

        status = IntHookObjectHookRegion(gVeHookObject,
                                         gGuest.Mm.SystemCr3,
                                         pSec->VirtualAddress + gVeDriverAddress,
                                         ROUND_UP((QWORD)pSec->Misc.VirtualSize, PAGE_SIZE),
                                         IG_EPT_HOOK_READ,
                                         IntVeHandleAccess,
                                         NULL, 0, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
        }

        if (0 != memcmp(pSec->Name, "VESTUB", sizeof("VESTUB")))
        {
            LOG("[VECORE] Hooking section %d (%s) with characteristics 0x%08x against executes\n",
                i, pSec->Name, pSec->Characteristics);

            status = IntHookObjectHookRegion(gVeHookObject,
                                             gGuest.Mm.SystemCr3,
                                             pSec->VirtualAddress + gVeDriverAddress,
                                             ROUND_UP((QWORD)pSec->Misc.VirtualSize, PAGE_SIZE),
                                             IG_EPT_HOOK_EXECUTE,
                                             IntVeHandleAccess,
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
IntVeEnableDisableDriverAccessInProtectedView(
    _In_ BOOLEAN Enable
    )
///
/// @brief Protect the VE driver inside the protected EPT view.
///
/// This function protects the VE driver inside the protected EPT view. This is needed, in order to remove
/// access rights which are not needed. This function removes write access from all read-only sections and
/// removes execute access from all data sections. Basically, it makes the EPT access rights reflect the
/// page-tables access rights.
///
/// @param[in]  Enable  If true, enables protection. Otherwise, it disables protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the VE image was not loaded.
///
{
    INTSTATUS status;
    PIMAGE_SECTION_HEADER pSec = NULL;
    DWORD sectionRva = 0;
    DWORD sectionCount = 0;

    if (NULL == gVeLoadedImageBuffer)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntPeListSectionsHeaders(0, gVeLoadedImageBuffer, gVeDriverSize, &sectionRva, &sectionCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeIterateSections failed with status: 0x%08x\n", status);
        return status;
    }

    pSec = (IMAGE_SECTION_HEADER *)(gVeLoadedImageBuffer + sectionRva);
    for (DWORD i = 0; i < sectionCount; i++, pSec++)
    {
        BYTE r, w, x;

        if (Enable)
        {
            r = 1;
            w = !!(pSec->Characteristics & IMAGE_SCN_MEM_WRITE) || (0 == memcmp(pSec->Name, "VEINS", 5));
            x = !!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) || (0 == memcmp(pSec->Name, "VEINS", 5));
        }
        else
        {
            r = w = 1;
            x = 0;
        }

        for (QWORD gva = 0; gva < pSec->Misc.VirtualSize; gva += 0x1000)
        {
            QWORD gpa;

            status = IntTranslateVirtualAddress(gVeDriverAddress + gva + pSec->VirtualAddress,
                                                gGuest.Mm.SystemCr3, &gpa);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntTranslateVirtualAddress failed for GVA %llx: 0x%08x\n", gva, status);
                break;
            }

            status = IntSetEPTPageProtection(gGuest.ProtectedEptIndex, gpa, r, w, x);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSetEPTPageProtectionEx failed for GPA %llx: 0x%08x\n", gpa, status);
                break;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeLockDriver(
    void
    )
///
/// @brief Monitors all the VE agent pages against translation modifications.
///
/// This function places a swap hook on each page belonging to the VE agent. This is needed in order to
/// copy the contents of the swapped pages when their translation is modified, and to move the VE info
/// pages, if they are swapped. Take a look at #IntVeHandleSwap for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    DWORD pgCount = gVeDriverSize / PAGE_SIZE;

    gVeDriverPages = HpAllocWithTag(pgCount * sizeof(void *), IC_TAG_VEPG);
    if (NULL == gVeDriverPages)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    LOG("Hooking PTs...\n");

    for (DWORD page = 0; page < gVeDriverSize; page += PAGE_SIZE)
    {
        // The SWAP hook on the #VE agent pages must be high priority, because we need to copy the real agent contents
        // inside the new page BEFORE doing the integrity checks.
        status = IntHookGvaSetHook(0, gVeDriverAddress + page, PAGE_SIZE, IG_EPT_HOOK_NONE, IntVeHandleSwap,
                                   NULL, NULL, HOOK_FLG_HIGH_PRIORITY, (PHOOK_GVA *)&gVeDriverPages[page / PAGE_SIZE]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeUnlockDriver(
    void
    )
///
/// @brief Removes the translation hook from the VE agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the swap hook has not been previously set.
///
{
    INTSTATUS status;

    if (NULL == gVeDriverPages)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    for (DWORD page = 0; page < gVeDriverSize; page += PAGE_SIZE)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&gVeDriverPages[page / PAGE_SIZE], 0);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }
    }

    HpFreeAndNullWithTag(&gVeDriverPages, IC_TAG_VEPG);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeSetVeInfoPage(
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoPageGva
    )
///
/// @brief Sets the VE info page on the provided VCPU.
///
/// This function registers the VE info page on the indicated VCPU. It also keeps a mapped cache of each
/// VE info page, as it needs to be accessed by Introcore when the VE agent initiates a hyper-call.
/// If a VE info page has been already registered, it will be overwritten.
///
/// @param[in]  CpuNumber       The VCPU number on which to set the VE info page.
/// @param[in]  VeInfoPageGva   Guest virtual address of the VE info page.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD veinfoGpa;

    if (NULL != gGuest.VcpuArray[CpuNumber].VeInfoPage)
    {
        IntPhysMemUnmap(&gGuest.VcpuArray[CpuNumber].VeInfoPage);

        // This is used to disable #VE on this VCPU.
#ifdef USER_MODE
        veinfoGpa = ~0ULL;
#else
        veinfoGpa = 0;
#endif // USER_MODE

        LOG("[VECORE] Setting the #VE info page on CPU %d at %llx/%llx\n", CpuNumber, VeInfoPageGva, veinfoGpa);

        status = IntSetVEInfoPage(CpuNumber, veinfoGpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetVEInfoPage failed: 0x%08x\n", status);
        }
    }

    if (0 != VeInfoPageGva)
    {
        status = IntTranslateVirtualAddress(VeInfoPageGva, gGuest.Mm.SystemCr3, &veinfoGpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddress failed: 0x%08x\n", status);
            return status;
        }

        status = IntPhysMemMap(veinfoGpa, PAGE_SIZE, 0, &gGuest.VcpuArray[CpuNumber].VeInfoPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            return status;
        }

        LOG("[VECORE] Setting the #VE info page on CPU %d at %llx/%llx\n", CpuNumber, VeInfoPageGva, veinfoGpa);

        status = IntSetVEInfoPage(CpuNumber, veinfoGpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetVEInfoPage failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeDeployLoader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called once the VE loaded has been injected.
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

    LOG("[VECORE] #VE loader deployed!\n");

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeCompleteLoader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD ErrorCode,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called once the VE loader has finished execution.
///
/// If VE agent injection failed, it will try to inject the PT filter, if the option is enabled. If VE agent
/// injection succeeded, it will enable VE filtering, by marking all the page-table pages as convertible
/// inside EPT. Once the VCPUs are resumed, no more EPT violations will be triggered on page-tables, instead
/// virtualization exceptions will be delivered to the VE agent inside the guest.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  ErrorCode           Injection error code. Must be 0 on success.
/// @param[in]  AgentTag            Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    if (ErrorCode != 0 || gVeLoadFailed)
    {
        ERROR("[ERROR] #VE driver injection failed with error 0x%08x, load failed: %s, will bail out.\n", ErrorCode,
              gVeLoadFailed ? "yes" : "no");

        gGuest.CoreOptions.Current &= ~INTRO_OPT_VE;

        if (gGuest.PtFilterFlagRemoved)
        {
            LOG("[INFO] Will activate INTRO_OPT_IN_GUEST_PT_FILTER because the flag has been removed "
                "due to INTRO_OPT_VE\n");

            gGuest.CoreOptions.Current |= INTRO_OPT_IN_GUEST_PT_FILTER;

            IntPtiInjectPtFilter();
        }

        IntVeResetState();

        return INT_STATUS_SUCCESS;
    }

    gVePendingDeploy = FALSE;
    gVeDeployed = TRUE;

    IntPauseVcpus();

    // Enable #VE in the hooks system. We can now handle #VEs.
    status = IntHookGpaEnableVe();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaEnableVe failed: 0x%08x\n", status);
        IntEnterDebugger();
    }

    IntResumeVcpus();

    LOG("[VECORE] #VE driver loaded successfully!\n");

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVeDeployUnloader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called after the boot driver (VE unloader) has been successfully injected.
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

    // Disable #VE in the hooks system. From now on, there will be no #VEs generated.
    IntHookGpaDisableVe();

    LOG("[VECORE] #VE unloader deployed!\n");

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVePatchVeCoreJmpTrampoline(
    _In_ QWORD Address,
    _In_ QWORD Target
    )
///
/// @brief Patches the VE trampoline inside the guest VE handler.
///
/// This function overwrites the VE handler with the following code sequence:
///         CALL next
///         LFENCE
/// next:   MOV dword [rsp], new_handler_low
///         MOV dword [rsp + 4], new_handler_high
///         RET
/// This function is not vulnerable to Spectre, as it is retpoline-like.
///
/// @param[in]  Address     Guest virtual address of the OS VE handler.
/// @param[in]  Target      Guest virtual address of the new VE handler.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD iidx = 0;
    BYTE buff[VE_TRAMPO_SIZE];

    // CALL $+4
    buff[iidx++] = 0xE8;
    buff[iidx++] = 0x03;
    buff[iidx++] = 0x00;
    buff[iidx++] = 0x00;
    buff[iidx++] = 0x00;

    // LFENCE
    buff[iidx++] = 0x0F;
    buff[iidx++] = 0xAE;
    buff[iidx++] = 0xE8;

    // MOV dword [rsp], NewHandle low
    buff[iidx++] = 0xC7;
    buff[iidx++] = 0x04;
    buff[iidx++] = 0x24;
    buff[iidx++] = (Target >> 0) & 0xFF;
    buff[iidx++] = (Target >> 8) & 0xFF;
    buff[iidx++] = (Target >> 16) & 0xFF;
    buff[iidx++] = (Target >> 24) & 0xFF;

    // MOV dword [rsp + 4], NewHandle high
    buff[iidx++] = 0xC7;
    buff[iidx++] = 0x44;
    buff[iidx++] = 0x24;
    buff[iidx++] = 0x04;
    buff[iidx++] = (Target >> 32) & 0xFF;
    buff[iidx++] = (Target >> 40) & 0xFF;
    buff[iidx++] = (Target >> 48) & 0xFF;
    buff[iidx++] = (Target >> 56) & 0xFF;

    buff[iidx++] = 0xC3;

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, Address, iidx, buff, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed for GVA %llx: 0x%08x\n", Address, status);
    }

    return status;
}


static INTSTATUS
IntVePatchVeCoreJmpKiKernelExit(
    _In_ QWORD VeCoreJmpKiKernelExitAddress
    )
///
/// @brief This function patches the VE code responsible of jumping to the KiKernelExit routine.
///
/// Depending on the mode of operation (KPTI on/off), we need to invoke the original KiKernelExit routine
/// to safely leave kernel space, if a VE originated in user space. Therefore, this code makes sure to
/// modify the VE code in such a way that it safely returns into user-space, by using the OS function.
/// NOTE: The KiKernelExit is responsibility of loading the user-mode Cr3 on returns from kernel.
/// NOTE: Since we place a code hook on the OS VE handler, the kernel-mode Cr3 is loaded by the OS.
/// The VE agent has nothing to do with loading the kernel or user Cr3 on transitions, as it leaves
/// this responsibility entirely to the OS.
///
/// @param[in]  VeCoreJmpKiKernelExitAddress    The address of the VeCoreJumpToKiKernelExit function inside the agent.
///
/// @retval #INT_STATUS_SUCCESS  On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If KPTI is not enabled, and we can safely return to user-space ourselves.
///
{
    INTSTATUS status;
    QWORD kiKernelExit = 0;

    if (!gGuest.KptiActive)
    {
        // The size of this array must match the size of the trampoline code, which is 24 bytes!
        BYTE nopbuff[VE_TRAMPO_SIZE] =
        {
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
        };

        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, VeCoreJmpKiKernelExitAddress,
                                     sizeof(nopbuff), nopbuff, IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed for GVA %llx: 0x%08x\n", VeCoreJmpKiKernelExitAddress, status);
        }

        return status;
    }

    status = IntVeFindKernelKvaShadowAndKernelExit(&kiKernelExit);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeFindKernelKvaShadowAndKernelExit failed: 0x%08x\n", status);
        return status;
    }
    else if (INT_STATUS_NOT_NEEDED_HINT == status)
    {
        return status;
    }

    LOG("[INFO] Found KiKernelExit @ %llx\n", kiKernelExit);

    return IntVePatchVeCoreJmpTrampoline(VeCoreJmpKiKernelExitAddress, kiKernelExit);
}


static QWORD
IntVeDeliverDriverForLoad(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD MaxSize,
    _In_opt_ void *Context
    )
///
/// @brief Initializes the VE driver agent inside the guest.
///
/// This function is responsibility of initializing the VE driver agent inside the guest space. Initialization
/// is done entirely by this function: no initialization steps are carried by the OS, making the loading
/// operation as secure as possible. The steps taken by this initialization function are the following:
/// 1. Load & write the VE driver image inside the guest space;
/// 2. Patch the VeCoreProtectedEptIndex - as the protected EPT index cannot be hard-coded, we need to dynamically
///    patch it inside the VE driver at load time. This can be whatever value the HV returns when creating the
///    protected EPT.
/// 3. Similar for the VeCoreUntrustedEptIndex. This cannot be hard-coded, the untrusted EPT index could be
///    whatever the HV chose to.
/// 4. Patch the VeCoreSelfMapIndex. This global variable contains the self map index (entry index inside the PML4
///    which maps itself).
/// 5. Patch the VeCoreMonitoredPtBits. This global variable tells the VE agent which bits inside the page-table
///    should generate an exit on, should they modify. This can be dynamically modified.
/// 6. Patch VeCoreJumpToKiKernelExit. This is needed in order to safely leave kernel space if KPTI is on.
/// 7. Hook the guest VE handler, and make it point to our handler.
/// 8. Initialize the VCPU map. This is used by the VE agent in order to determine the VCPU index a VE was generated
///    on. Note that we cannot use CPUID, since it generates a VM exit, which would cancer most of the VE optimization.
/// 9. Protect the VE agent inside the untrusted EPT view.
/// 10. Protect the VE agent inside the protected EPT view.
/// 11. Place a swap hook on each page of the agent.
/// 12. Initialize the VE info pages.
/// Once we resume the VCPUs, the guest can generate virtualization exceptions. However, we make pages convertible
/// only after the loader has finished, in order to make sure the initialization succeeded.
/// NOTE: Any failure in this function will cause the VE agent to be removed, and VE filtering to be disabled.
///
/// @param[in]  GuestVirtualAddress Guest virtual address where the VE agent is deployed.
/// @param[in]  MaxSize             Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD rva = 0, codelen = 0;
    PBYTE pImage;
    BYTE oldcode[64];
    QWORD newvehnd = 0, oldvehnd = 0, relevantbits = HOOK_PTS_MONITORED_BITS, vepages, vestacks;
    QWORD ret = 1;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MaxSize);

    pImage = HpAllocWithTag(gVeDriverSize, IC_TAG_ALLOC);
    if (NULL == pImage)
    {
        return ret;
    }

    LOG("[VECORE] Delivering the #VE agent at GVA %llx...\n", GuestVirtualAddress);

    gVeDriverAddress = GuestVirtualAddress;

    IntPauseVcpus();

    gVeLoadedImageBuffer = pImage;


    // Load the image & prepare it for execution.
    status = IntLdrLoadPEImage(gVeDriverx64, sizeof(gVeDriverx64), GuestVirtualAddress,
                               pImage, gVeDriverSize, LDR_FLAG_FIX_RELOCATIONS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrLoadPEImage failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }


    // Deploy the #VE driver inside the guest.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress, gVeDriverSize, pImage, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] The #VE agent was written at GVA %llx!\n", GuestVirtualAddress);


    // Get the VeCoreProtectedEptIndex export - this points to the "mov ecx, ept_index" instruction which must be
    // patched in order to reflect the actual protected EPT index (which could be any value).
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreProtectedEptIndex", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Patch the "mov ecx, ept_index" instruction with the actual ept index - we will modify the immediate of the
    // "mov ecx" instruction.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva, 4,
                                 &gGuest.ProtectedEptIndex, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Patched protected EPT index %d at %llx!\n", gGuest.ProtectedEptIndex, GuestVirtualAddress + rva);


    // Get the VeCoreUntrustedEptIndex export - this points to the "mov ecx, ept_index" instruction which must be
    // patched in order to reflect the actual untrusted EPT index (which could be any value). Normally, we could use
    // the value saved by the CPU inside the #VE info page, but due to an errata, on Xeon Gold 5118, that value will
    // always be 0.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreUntrustedEptIndex", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Patch the "mov ecx, ept_index" instruction with the actual ept index - we will modify the immediate of the
    // "mov ecx" instruction.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva, 4,
                                 &gGuest.UntrustedEptIndex, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Patched untrusted EPT index %d at %llx!\n", gGuest.UntrustedEptIndex, GuestVirtualAddress + rva);


    // Get the VeCoreSelfMapIndex export - this points to the self-map index inside the page-tables, and we will patch
    // it to reflect the actual self-map index inside the PTs.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreSelfMapIndex", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Patch the VeCoreSelfMapIndex value inside the VE driver.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva, 4,
                                 &gGuest.Mm.SelfMapIndex, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Patched self-map index %d at %llx!\n", gGuest.Mm.SelfMapIndex, GuestVirtualAddress + rva);


    // Get the VeCoreMonitoredPtBits export -this contains the bits that we wish to monitor inside a page-table.
    // This value can be changed while the HVI is active in order to enable/disable hypercalls on different bits.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreMonitoredPtBits", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Patch the VeCoreMonitoredPtBits value inside the VE driver.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva, 8, &relevantbits, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Patched relevant-bits value 0x%016llx at %llx!\n", relevantbits, GuestVirtualAddress + rva);


    // Get the VeCoreJumpToKiKernelExit export - this is where the "jump to KiKernelExit" trampoline is situated,
    // so that we exit gracefully from the #VE handler
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreJumpToKiKernelExit", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Now patch the VeCoreJumpBack code
    status = IntVePatchVeCoreJmpKiKernelExit(GuestVirtualAddress + rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVePatchVeCoreJumpBack failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Patched VeCoreJumpToKiKernelExit code at %llx\n", GuestVirtualAddress + rva);


    // Initialize the #VE info pages & #VE stacks. Once we do this, the #VE agent is ready to accept #VEs.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreVePages", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed for VeCoreVePages: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    vepages = gVeInfoPages = GuestVirtualAddress + rva;

    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreVeStacks", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed VeCoreVeStacks: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    vestacks = GuestVirtualAddress + rva;

    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreCache", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed VeCoreCache: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    gVeCache = GuestVirtualAddress + rva;

    LOG("[VECORE] #VE info pages at 0x%016llx\n", vepages);
    LOG("[VECORE] #VE stacks at 0x%016llx\n", vestacks);
    LOG("[VECORE] #VE page cache 0x%016llx\n", gVeCache);


    // Get the Introspection #VE handler address and hook the int 20 exception handler inside the guest.
    if (gGuest.OSVersion < 16299 && gGuest.KptiActive)
    {
        // Windows 7, 8, 8.1, TH1, TH2, RS1 or RS2, with KPTI - the stub is "PUSH 0x14/JMP KiIsrThunkShadow".
        status = IntPeFindExportByName(gVeDriverAddress, gVeLoadedImageBuffer,
                                       "VeCoreVirtualizationExceptionHandlerKPTI", &rva);
    }
    else if (gGuest.OSVersion < 16299 && !gGuest.KptiActive)
    {
        // Windows 7, 8, 8.1, TH1, TH2, RS1 or RS2, without KPTI - the stub is
        // "PUSH 0x14/PUSH rbp/JMP KiIsrThunkShadow".
        status = IntPeFindExportByName(gVeDriverAddress, gVeLoadedImageBuffer,
                                       "VeCoreVirtualizationExceptionHandlerNoKPTI", &rva);
    }
    else
    {
        // Windows RS3 and newer - same treatment with/without KPTI, because it is aware of the VirtualizationException.
        status = IntPeFindExportByName(gVeDriverAddress, gVeLoadedImageBuffer,
                                       "VeCoreVirtualizationExceptionHandler", &rva);
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    newvehnd = gVeDriverAddress + rva;

    // Hook the #VE handler and make it point inside our driver.
    status = IntWinApiHookVeHandler(newvehnd, &gVeHandlerCloak, &oldvehnd, &codelen, oldcode);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinApiHookVeHandler failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Hooked the #VE handler, old handler at %llx, new handler at %llx!\n", oldvehnd, newvehnd);


    // Store the original code. We need it when we have to execute the original handler. This will usually happen on
    // older Windows versions, which are not aware of the Virtualization Exception, and will generically handle
    // int 20 as a spurious event.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreReplacedCode", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Write the original code inside the dedicated area of our #VE agent.
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva, codelen, oldcode, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Write the jump-back handler code.
    // Store the original code. We need it when we have to execute the original handler.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCoreJumpToReplacedCode", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntVePatchVeCoreJmpTrampoline(GuestVirtualAddress + rva, oldvehnd + codelen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVePatchVeCoreJmpTrampoline failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Initialize the CPU map. We use the PCR as a key to determine the current CPU index.
    status = IntPeFindExportByName(GuestVirtualAddress, pImage, "VeCpuMap", &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        // Check out which logical CPU VCPU i is inside the guest. In order to do so, we use the guest algorithm,
        // which is based on the limit of GDT descriptor 0x50.
        QWORD gdtbase, desc;
        WORD gdtlimit;
        DWORD cpuid;
        DWORD limit;

        // We could also check the IDT here, which will be at 0 (the CPU is in real mode)
        if (__unlikely(!gGuest.VcpuArray[i].Initialized))
        {
            TRACE("[VECORE] VCPU %u is not used by the guest, will skip it\n", i);
            continue;
        }

        // Get the GDT base & limit on the designated VCPU.
        status = IntGdtFindBase(i, &gdtbase, &gdtlimit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGdtFindBase failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Make sure descriptor 0x50 is valid.
        if (gdtlimit < 0x57)
        {
            ERROR("[ERROR] GDT 0x%016llx on CPU %u has limit %u, which is too small!\n", gdtbase, i, gdtlimit);
            status = INT_STATUS_NOT_SUPPORTED;
            goto cleanup_and_exit;
        }

        // Read the descriptor.
        status = IntKernVirtMemRead(gdtbase + 0x50, 8, &desc, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Compute the segment limit.
        limit = ((desc & 0xFFFF) | ((desc & 0x000F000000000000) >> 32)) << ((desc & 0x80000000000000) ? 12 : 0);

        cpuid = ((limit & 0x3FF) << 6) | (limit >> 14);

        LOG("[VECORE] VCPU %d maps on guest CPU %d, GDT entry is 0x%016llx\n", i, cpuid, desc);

        // Write the mapping.
        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, GuestVirtualAddress + rva + cpuid * 4ull,
                                     4, &i, IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }


    // Now hook the #VE agent, and protect it against modifications/PT alterations.

    // Create a hook object for the #VE driver.
    status = IntHookObjectCreate(0, gGuest.Mm.SystemCr3, &gVeHookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Hook the #VE driver inside the guest - we won't allow any rights to take place on it.
    status = IntVeHookVeDriver();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeHookVeDriver failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] #VE driver hooked in guest view!\n");


    // Enable execute rights for the #VE inside the protected view.
    status = IntVeEnableDisableDriverAccessInProtectedView(TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeEnableDisableDriverAccessInProtectedView failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] #VE driver hooked in protected view!\n");


    // Lock the #VE driver.
    status = IntVeLockDriver();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeLockDriver failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] #VE driver locked in memory!\n");


    for (QWORD i = 0; i < gGuest.CpuCount; i++)
    {
        // Set the #VE info page for this VCPU.
        status = IntVeSetVeInfoPage((DWORD)i, vepages + PAGE_SIZE * i);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeSetVeInfoPage failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Initialize the (few) required fields inside the #VE info page.
        gGuest.VcpuArray[i].VeInfoPage->ProtectedStack = (PBYTE)(vestacks + VE_STACK_SIZE * i) + VE_STACK_SIZE - 16;
        gGuest.VcpuArray[i].VeInfoPage->Self = vepages + PAGE_SIZE * i;
        gGuest.VcpuArray[i].VeInfoPage->Index = i;
    }

    LOG("[VECORE] Initialized the #VE info paged at 0x%016llx, stacks at 0x%016llx!\n", vepages, vestacks);


    // All done!

    // Add BaseVa and size of #VE Agent.
    gVeModule.BaseVa = GuestVirtualAddress;
    gVeModule.Size = gVeDriverSize;

    status = INT_STATUS_SUCCESS;

    ret = 0;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Something failed during #VE load, will unload it!\n");
        gVeLoadFailed = TRUE;
        IntVeRemoveAgent(0);
    }

    IntResumeVcpus();

    return ret;
}


static INTSTATUS
IntVeUnhookVeAgent(
    void
    )
///
/// @brief Removes the hooks placed on the VE agent.
///
/// This function will remove:
/// 1. The VE info pages; no more VEs can be generated;
/// 2. The VE handler hook cloak;
/// 3. The protection set on the agent inside the untrusted EPT;
/// 4. The protection set on the agent inside the protected EPT;
/// 5. The swap hooks placed on the agent pages
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    IntPauseVcpus();

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        status = IntVeSetVeInfoPage(i, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeSetVeInfoPage failed: 0x%08x\n", status);
        }
    }

    // Remove the #VE handler cloak.
    if (NULL != gVeHandlerCloak)
    {
        status = IntMemClkUncloakRegion(gVeHandlerCloak, MEMCLOAK_OPT_APPLY_PATCH);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
        }

        gVeHandlerCloak = NULL;
    }

    // Remove the #VE agent hooks.
    if (NULL != gVeHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gVeHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroyFastSafe failed: 0x%08x\n", status);
        }
    }

    LOG("[VECORE] Successfully removed agent protection in default view!\n");

    // Remove the #VE driver lock.
    status = IntVeUnlockDriver();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeUnlockDriver failed: 0x%08x\n", status);
    }

    // Remove executable rights on the agent inside protected view.
    status = IntVeEnableDisableDriverAccessInProtectedView(FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeEnableDisableDriverAccessInProtectedView failed: 0x%08x\n", status);
    }

    IntResumeVcpus();

    LOG("[VECORE] Successfully removed agent protection in protected view!\n");

    if (NULL != gVeLoadedImageBuffer)
    {
        HpFreeAndNullWithTag(&gVeLoadedImageBuffer, IC_TAG_ALLOC);
    }

    return status;
}


static QWORD
IntVeDeliverDriverForUnload(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD MaxSize,
    _In_opt_ void *Context
    )
///
/// @brief Handles the unloading of the VE agent.
///
/// This function is invoked via the boot driver, when we wish to unload the VE agent. This function first checks
/// if the unloading can be carried safely (ie, there are no threads with RIPs pointing inside the agent); if it
/// is safe to unload it, the unload will proceed; otherwise, the in guest boot driver will spin for a while
/// before retrying to unload the VE agent.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  MaxSize             Unused.
/// @param[in]  Context             Unused.
///
/// @retval 0 if the unload can proceed, 1 otherwise.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MaxSize);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    // Make sure there are no RIPs inside the agent.
    IntPauseVcpus();

    status = IntThrSafeCheckThreads(THS_CHECK_ONLY | THS_CHECK_VEFILTER);
    if (INT_STATUS_CANNOT_UNLOAD == status)
    {
        LOG("[WARNING] Cannot unload yet, RIPs still point inside the filter!\n");
        IntResumeVcpus();
        return 1;
    }

    status = IntVeUnhookVeAgent();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeUnhookVeAgent failed: 0x%08x\n", status);
    }

    // Unamp the #VE cache pages.
    for (DWORD i = 0; i < VE_CACHE_LINES; i++)
    {
        if (NULL != gVeCachePages[i].Page)
        {
            IntVirtMemUnmap(&gVeCachePages[i].Page);
        }
    }

    IntResumeVcpus();

    LOG("[VECORE] #VE driver unloaded successfully!\n");

    return 0;
}


static void
IntVeResetState(
    void
    )
///
/// @brief Reset the VE state.
///
{
    gVePendingUnload = gVeDeployed = gVePendingDeploy = gVeLoadFailed = FALSE;
    gVeDriverAddress = 0;
    gVeInfoPages = 0;
    gVeCache = 0;
}


static INTSTATUS
IntVeCompleteUnloader(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD ErrorCode,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Finishes the unload procedure, by resetting the state and the power-state spin wait.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  ErrorCode           Unused.
/// @param[in]  AgentTag            Unused.
/// @param[in]  Context             Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AgentTag);
    UNREFERENCED_PARAMETER(ErrorCode);
    UNREFERENCED_PARAMETER(GuestVirtualAddress);

    IntVeResetState();

    LOG("[VECORE] #VE driver unloaded successfully!\n");

    status = IntWinPowDisableSpinWait();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinPowDisableSpinWait failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntVeHandleHypercall(
    _In_ DWORD CpuNumber
    )
///
/// @brief Handles hyper calls initiated by the VE agent.
///
/// This function handles VE agent VMCALLs. Only a few are defined:
/// 1. NOP - does nothing, just causes an exit.
/// 2. BREAK - break into debugger; initiates when the VE agent encounters an exceptional condition that prevents
///    it from safely continuing execution.
/// 3. TRACE - logs some information.
/// 4. RAISE EPT - this is the main hyper call, used to raise an EPT violation from a VE that took place inside the
///    guest.
///
/// @param[in]  CpuNumber   Guest VCPU number on which the VMCALL was issued.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If an unsupported VMCALL number is raised.
/// @retval #INT_STATUS_RAISE_EPT If an EPT must be raised. This will cause the VMCALL
///         handler to invoke the EPT violation handler, as if a regular memory access took place.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS regs;

    status = INT_STATUS_SUCCESS;
    regs = &gVcpu->Regs;

    if (regs->Rdx == VE_HCALL_NOP)
    {
        // Do nothing.
    }
    else if (regs->Rdx == VE_HCALL_BREAK)
    {
        // Break in debugger.
        LOG("Breaking in debugger due to #VE request, reason 0x%016llx, argument 0x%016llx.\n",
            regs->Rbx, regs->Rcx);
        IntVeDumpVeInfoPage(gVcpu->Index);
        LOG("==============================================================================================\n");
        LOG("==============================================================================================\n");
        LOG("==============================================================================================\n");
        LOG("==============================================================================================\n");
        IntVeDumpVeInfoPages();
        LOG("==============================================================================================\n");
        IntEnterDebugger();
    }
    else if (regs->Rdx == VE_HCALL_TRACE)
    {
        LOG("$$$$ #VE on CPU %d/%lld/%lld, #VE info page at 0x%016llx, self at 0x%016llx, "
            "GLA 0x%016llx, GPA 0x%016llx, QUAL 0x%016llx\n",
            gVcpu->Index, regs->Rbx, regs->Rcx, gVcpu->VeInfoPage->Self, gVcpu->VeInfoPage->Index,
            gVcpu->VeInfoPage->GuestLinearAddress, gVcpu->VeInfoPage->GuestPhysicalAddress,
            gVcpu->VeInfoPage->Qualification);

        IntVeDumpVeInfoPage(CpuNumber);
    }
    else if (regs->Rdx == VE_HCALL_RAISE_EPT)
    {
        // Invoke the #VE hypercall handler.
        if (NULL == gVcpu->VeInfoPage)
        {
            ERROR("[ERROR] Trying to raise EPT violation with NULL #VE info page!\n");
            IntEnterDebugger();
        }

        status = INT_STATUS_RAISE_EPT;
    }
    else
    {
        ERROR("[ERROR] Unknown #VE hypercall number %lld!\n", regs->Rdx);
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntVeDeployAgent(
    void
    )
///
/// @brief Inject the VE agent inside the guest.
///
/// NOTE: If this function returns success, it does not mean that the VE agent has been successfully injected. It just
/// means that it has been successfully scheduled for injection. Failures may still happen during the injection itself.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the VE system has not been initialized.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If the VE agent has already been injected.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the OS is not 64 bit Windows.
///
{
    if (!gVeVeInitialized)
    {
        WARNING("[WARNING] Cannot inject the #VE agent, because #VE is not supported!\n");
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (gGuest.UninitPrepared)
    {
        WARNING("[WARNING] Cannot inject the #VE agent, because uninit is being prepared!\n");
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (gVeDeployed || gVePendingDeploy || gVePendingUnload)
    {
        WARNING("[WARNING] Cannot inject the #VE agent, because an agent is already %s!\n",
                gVeDeployed ? "deployed" : gVePendingDeploy ? "pending deploy" : "pending unload");
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    // We only support #VE on Windows x64
    if (gGuest.OSType != introGuestWindows || !gGuest.Guest64)
    {
        WARNING("[WARNING] Cannot inject the #VE agent, because it is only supported on x64 Windows!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    gVeDriverAddress = 0;
    gVeInfoPages = 0;

    gVePendingDeploy = TRUE;

    return IntWinAgentInject(IntVeDeployLoader, IntVeCompleteLoader, IntVeDeliverDriverForLoad,
                             NULL, gVeDriverx64, gVeDriverSize, TRUE, IG_AGENT_TAG_VE_DRIVER, AGENT_TYPE_VE_LOADER,
                             NULL, 0, NULL, 0, NULL);
}


INTSTATUS
IntVeRemoveAgent(
    _In_ DWORD AgOpts
    )
///
/// @brief Removes the VE agent from guest memory.
///
/// NOTE: If this function returns success, it does not mean that the VE agent has been successfully removed from
/// the guest memory; it simply means it has been successfully scheduled for removal.
///
/// @param[in]  AgOpts  Agent options.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If VE has not been initialized.
///
{
    INTSTATUS status;

    if (!gVeVeInitialized)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!(gVeDeployed || gVePendingDeploy) || gVePendingUnload)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    //IntVeDumpStats();

    if (gGuest.BugCheckInProgress)
    {
        status = IntHookGpaDisableVe();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaDisableVe failed: 0x%08x\n", status);
        }

        status = IntVeUnhookVeAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeUnhookVeAgent failed: 0x%08x\n", status);
        }

        // Overwrite the whole driver with zeros.
        // This SHOULD be safe. We will only get here if `BugCheckInProgress` is set.
        // `BugCheckInProgress` will only be set if the guest reaches our hook inside
        // `KiDisplayBlueScreen` and by that time we *assume* that there's only one
        // VCPU running (with the rip inside our hook). Thus, there *shouldn't* be any
        // other VCPUs inside the VE agent.
        if (0 != gVeDriverAddress)
        {
            for (DWORD page = 0; page < gVeDriverSize; page += PAGE_SIZE)
            {
                PBYTE pMap;

                status = IntVirtMemMap(gVeDriverAddress + page, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pMap);
                if (!INT_SUCCESS(status))
                {
                    continue;
                }

                memzero(pMap, PAGE_SIZE);

                IntVirtMemUnmap(&pMap);
            }
        }

        IntVeResetState();

        LOG("[VECORE] #VE driver unloaded successfully!\n");

        return status;
    }

    gVePendingUnload = TRUE;

    return IntWinAgentInject(IntVeDeployUnloader, IntVeCompleteUnloader, IntVeDeliverDriverForUnload,
                             NULL, gVeDriverx64, sizeof(gVeDriverx64), TRUE,
                             IG_AGENT_TAG_VE_DRIVER, AGENT_TYPE_VE_UNLOADER,
                             NULL, AgOpts, NULL, 0, NULL);
}


QWORD
IntVeGetDriverAddress(
    void
    )
///
/// @brief Gets the guest virtual address of the VE agent.
///
/// @retval The guest virtual address where the VE agent was loaded.
///
{
    return gVeDriverAddress;
}


BOOLEAN
IntVeIsPtrInAgent(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    )
///
/// @brief Check if an address points inside the VE agent.
///
/// @param[in]  Ptr     The pointer to be checked.
/// @param[in]  Type    Pointer type: live RIP or stack value.
///
/// @retval True if the pointer points inside any of the VE agent components, false otherwise.
///
{
    if (0 == gVeDriverAddress)
    {
        return FALSE;
    }
    else
    {
        if (ptrLiveRip == Type)
        {
            QWORD vehnd;

            IntIdtGetEntry(IG_CURRENT_VCPU, 20, &vehnd);

            return (Ptr >= gVeDriverAddress && Ptr < gVeDriverAddress + gVeDriverSize) ||
                   (Ptr >= vehnd && Ptr < vehnd + 0x80) ||
                   (IntMemClkIsPtrInCloak(gVeHandlerCloak, Ptr));
        }
        else
        {
            // Since our agent runs with interrupts disabled and on separate stack, it is safe to always return false.
            return FALSE;
        }
    }
}


BOOLEAN
IntVeIsCurrentRipInAgent(
    void
    )
///
/// @brief Check if the current RIP points inside the VE agent.
///
/// This only checks of the current RIP points inside the agent. It doesn't care about the VE handler trampoline or
/// cloaked code, as we only call this to check if a VMCALL was initiated inside the VE agent.
///
/// @retval True if the current RIP points inside the agent, false otherwise.
///
{
    if (0 == gVeDriverAddress)
    {
        return FALSE;
    }

    return (gVcpu->Regs.Rip >= gVeDriverAddress && gVcpu->Regs.Rip < gVeDriverAddress + gVeDriverSize);
}


static INTSTATUS
IntVeFindKernelKvaShadowAndKernelExit(
    _Inout_ QWORD *KiKernelExit
    )
///
/// @brief Searches for the KvaShadow and KiKernelExit.
///
/// This function searches the NT image for the KiKernelExit function and the KvaShadow variable.
///
/// @param[in, out] KiKernelExit    The address of the KiKernelExit function inside guest space.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
#define MAX_INSTRUX_VE_KERNEL_OBJECTS_COUNT 1024

    DWORD instruxCount = 0;
    QWORD currentRip;
    BOOLEAN bIretqFound = FALSE;
    BOOLEAN bJmpFound = FALSE;
    INTSTATUS status = INT_STATUS_SUCCESS;
    PBYTE instruxBuffer = NULL;
    DWORD currentPosInBuff = 0;
    // keeps the current instruction size, used for going back in the buffer
    BYTE instruxSizes[MAX_INSTRUX_VE_KERNEL_OBJECTS_COUNT];
    QWORD kernelExit = 0, kvaShadow = 0;
    DWORD maxInstruxCount;
    BOOLEAN bMovCr3 = FALSE;

    if (!gGuest.KptiActive)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Main idea: disassemble an interrupt (e.g. #PF) and before the IRETQ and swapgs find KiKvaShadow and KiKernelExit
    instruxBuffer = HpAllocWithTag(PAGE_SIZE, IC_TAG_ALLOC);
    if (NULL == instruxBuffer)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    // Read the nt!KiPageFaultShadow address
    status = IntIdtGetEntry(IG_CURRENT_VCPU, VECTOR_PF, &currentRip);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIdtGetEntry failed for IDT base 0x%016llx: 0x%08x\n",
              gVcpu->IdtBase + IDT_DESC_SIZE64 * 14, status);
        goto cleanup_and_exit;
    }

    status = IntKernVirtMemRead(currentRip, PAGE_SIZE, instruxBuffer, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read the PF Shadow buffer: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    while (instruxCount < MAX_INSTRUX_VE_KERNEL_OBJECTS_COUNT && currentPosInBuff + 16 < PAGE_SIZE)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstructionFromBuffer(instruxBuffer + currentPosInBuff,
                                                   PAGE_SIZE - currentPosInBuff,
                                                   IG_CS_TYPE_64B,
                                                   &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if ((instrux.Instruction == ND_INS_MOV_CR) && ND_IS_OP_REG(&instrux.Operands[0], ND_REG_CR, 8, NDR_CR3))
        {
            bMovCr3 = TRUE;
        }

        // We get the first JMP after the MOV CR3 instruction from nt!KiPageFaultShadow, which will point to the
        // real nt!KiPageFault.
        if (instrux.Instruction == ND_INS_JMPNR && bMovCr3)
        {
            currentRip = currentRip + SIGN_EX(instrux.RelOffsLength, instrux.RelativeOffset) + instrux.Length;
            bJmpFound = TRUE;
            break;
        }

        instruxCount++;
        currentPosInBuff += instrux.Length;
        currentRip += instrux.Length;
    }

    if (!bJmpFound)
    {
        ERROR("[ERROR] Failed to find JMP after MOV CR3 instruction, bailing out!\n");

        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    // read the real nt!KiPageFault
    status = IntKernVirtMemRead(currentRip, PAGE_SIZE, instruxBuffer, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read the PF buffer: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    instruxCount = 0;
    currentPosInBuff = 0;

    while (instruxCount < MAX_INSTRUX_VE_KERNEL_OBJECTS_COUNT && currentPosInBuff + 16 < PAGE_SIZE)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstructionFromBuffer(instruxBuffer + currentPosInBuff, PAGE_SIZE - currentPosInBuff,
                                                   IG_CS_TYPE_64B, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if (instrux.Instruction == ND_INS_IRET)
        {
            bIretqFound = TRUE;
            break;
        }

        // We keep for each instruction the size of the instruction, so we can go back in the buffer
        instruxSizes[instruxCount] = instrux.Length;
        instruxCount++;
        currentPosInBuff += instrux.Length;
        currentRip += instrux.Length;
    }

    if (!bIretqFound)
    {
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    if (instruxCount == 0)
    {
        ERROR("[ERROR] We found an IRET as the first instruction in nt!KiPageFault, will bail out!\n");

        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    maxInstruxCount = instruxCount >= 5 ? instruxCount - 5 : 0;

    // now we go back (by decreasing the current position in buffer and the current RIP, using the already kept
    // instruction size in the instruxSizes array) until we find an JMP rel instruction
    for (DWORD i = instruxCount - 1; i >= maxInstruxCount; i--)
    {
        INSTRUX instrux;

        // Go back in the buffer with current instruction length bytes
        currentPosInBuff -= instruxSizes[i];
        currentRip -= instruxSizes[i];

        status = IntDecDecodeInstructionFromBuffer(instruxBuffer + currentPosInBuff, PAGE_SIZE - currentPosInBuff,
                                                   IG_CS_TYPE_64B, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Before IRETQ instruction, there will always be the following pattern:
        //  test [nt!KiKvaShadow], 1
        //  jne _to_swapgs_and_iretq
        //  jmp nt!KiKernelExit
        //_to_swapgs_and_iretq:
        //  swapgs
        //  iretq
        if (instrux.Instruction == ND_INS_JMPNR &&
            instrux.Operands[0].Type == ND_OP_OFFS)
        {
            kernelExit = currentRip + SIGN_EX(instrux.RelOffsLength, instrux.RelativeOffset) + instrux.Length;
        }
        else if (instrux.Instruction == ND_INS_TEST &&
                 instrux.Operands[0].Type == ND_OP_MEM &&
                 instrux.Operands[0].Info.Memory.IsRipRel &&
                 instrux.Operands[1].Type == ND_OP_IMM &&
                 instrux.Operands[1].Info.Immediate.Imm == 1)
        {
            // Note: we only get the address of KiKvaShadow for validation, we already have the KptiEnabled value
            // in gGuest.
            kvaShadow = currentRip + instrux.Operands[0].Info.Memory.Disp + instrux.Length;
        }

        if (kernelExit != 0 && kvaShadow != 0)
        {
            break;
        }
    }

    if (kernelExit == 0 || kvaShadow == 0)
    {
        status = INT_STATUS_NOT_FOUND;
    }

cleanup_and_exit:
    if (INT_SUCCESS(status))
    {
        *KiKernelExit = kernelExit;
    }

    if (NULL != instruxBuffer)
    {
        HpFreeAndNullWithTag(&instruxBuffer, IC_TAG_ALLOC);
    }

    return status;
}


INTSTATUS
IntVeInit(
    void
    )
///
/// @brief Initialize the VE system.
///
/// This function initializes the VE system. In order to do so, it makes sure the VE is supported on the system:
/// 1. VE must be supported;
/// 2. VMFUNC must be supported;
/// 3. At most #VE_MAX_CPUS VCPUs must be assigned to the guest;
/// 4. The Glue must contain all the VE related functions;
/// In order to carry on the initialization, this function:
/// 1. It creates a new EPT - the protected EPT;
/// 2. It gets the maximum guest physical address accessible by the guest;
/// 3. Makes the entire guest space non-executable inside the protected EPT view;
/// 4. It creates the VE module entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If VE is not supported on the system.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If there are GPA hooks set.
///
{
    INTSTATUS status;

    if (gVeVeInitialized)
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    if (!gGuest.SupportVE)
    {
        LOG("[INFO] No #VE support is present for guest, will not enable the #VE system!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!gGuest.SupportVMFUNC)
    {
        LOG("[INFO] No VMFUNC support is present for guest, will not enable the #VE system!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gGuest.CpuCount > VE_MAX_CPUS)
    {
        LOG("[INFO] The #VE agent supports max %d VCPUs, the guest currently has %d!\n", VE_MAX_CPUS, gGuest.CpuCount);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Make sure that there are no EPT hooks set
    for (DWORD i = 0; i < GPA_HOOK_TABLE_SIZE; i++)
    {
        if (__unlikely(!IsListEmpty(&gHooks->GpaHooks.GpaHooksExecute[i]) ||
                       !IsListEmpty(&gHooks->GpaHooks.GpaHooksRead[i]) ||
                       !IsListEmpty(&gHooks->GpaHooks.GpaHooksWrite[i])))
        {
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    // Make sure the #VE related API has been initialized by the integrator.
    if (!GlueIsVeApiAvailable())
    {
        TRACE("[VECORE] Required APIs not found, will not use #VE.\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    LOG("[INFO] #VE and VMFUNC support detected, will use the #VE filtering optimization!\n");

    // Create the protected EPT.
    status = IntCreateEPT(&gGuest.ProtectedEptIndex);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCreateEPT failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[INFO] Untrusted EPT index is: %d, Protected EPT index is: %d\n",
        gGuest.UntrustedEptIndex, gGuest.ProtectedEptIndex);

    status = IntGuestGetLastGpa(&gVeMaxGpa);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestGetLastGpa failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    TRACE("[VECORE] Max physical address for guest: 0x%016llx\n", gVeMaxGpa);

    // Protected EPT successfully created, now mark it as RW-. We want execute rights only for the agent.
    for (QWORD gpa = 0; gpa < gVeMaxGpa; gpa += 0x1000)
    {
        // The pages are not convertible, by default. We want to keep them that way.
        IntSetEPTPageProtection(gGuest.ProtectedEptIndex, gpa, 1, 1, 0);

        // Xen/KVM populate newly created EPT lazily. This means that by default, all entries inside the newly created
        // EPT will be 0 (not present). However, a NULL entry also has the not convertible bit cleared, which means that
        // #VE can be generated for that particular entry. As a result, whenever a page which hasn't been accessed yet
        // is read/written/executed for the first time, we will get a #VE. However, the agent cannot handle such #VEs,
        // which must be converted to EPT violations for the HV to handle by filling in the entry inside the EPT.
        // As a workaround, we can iterate the entire guest physical memory space and forcefully modify the access
        // rights for each physical page. This will ensure us that those pages will be committed inside the newly
        // created EPT, and as a result, no spurious #VEs can be generated on pages which were not yet migrated to the
        // new EPT.
        // Also note that since this code is executed during init, there are no HVI hooks set whatsoever. As a result,
        // we can simply mark each physical page with full rights (RWX). Devices will be filtered out by the HV.
        // We only do this if the untrusted EPT is not the default one (for example, we don't have to do this
        // on Napoca).
        if (gGuest.UntrustedEptIndex != 0)
        {
            IntSetEPTPageProtection(gGuest.UntrustedEptIndex, gpa, 1, 1, 1);
        }
    }

    // Get the #VE driver info.
    status = IntLdrGetImageSizeAndEntryPoint(gVeDriverx64, sizeof(gVeDriverx64), &gVeDriverSize, &gVeDriverEntryPoint);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrGetImageSizeAndEntryPoint failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Add relevant information to the static gVeModule
    memset(&gVeModule, 0, sizeof(gVeModule));

    gVeModule.Protected = TRUE;
    gVeModule.ProtectionFlag = INTRO_OPT_VE;

    gVeModule.NameLength = sizeof(VE_DRV_NAME) / 2 - 1;
    gVeModule.Name = VE_DRV_NAME;
    gVeModule.NameHash = kmExcNameVeAgent;

    gVeModule.Win.PathLength = sizeof(VE_DRV_PATH) / 2 - 1;
    gVeModule.Win.Path = VE_DRV_PATH;
    gVeModule.Win.PathHash = Crc32Compute(gVeModule.Win.Path, sizeof(VE_DRV_PATH) - 2, INITIAL_CRC_VALUE);

    gVeModule.Win.MzPeHeaders = gVeDriverx64;

    // Note that BaseVa and Size are set in IntVeDeliverDriverForLoad because at this time we don't know them

    LOG("[VECORE] Successfully added all the relevant info in gVeModule!\n");

    gVeVeInitialized = gGuest.VeInitialized = TRUE;

    // All good!
    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (INVALID_EPTP_INDEX != gGuest.ProtectedEptIndex)
        {
            IntDestroyEPT(gGuest.ProtectedEptIndex);
        }

        // Don't destroy the untrusted EPT index, we'll continue to use it.
    }

    return status;
}


INTSTATUS
IntVeUnInit(
    void
    )
///
/// @brief Uninit the VE system.
///
/// This function uninits the VE system. It will destroy the protected EPT. Note that this function does not
/// remove the VE agent from guest memory, it simply uninitializes the VE system. This function should be
/// called only during Introcore uninit.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (!gVeVeInitialized)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Destroy the protected EPT.
    if (INVALID_EPTP_INDEX != gGuest.ProtectedEptIndex)
    {
        status = IntDestroyEPT(gGuest.ProtectedEptIndex);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDestroyEPT failed: 0x%08x\n", status);
        }
    }

    if (NULL != gVeLoadedImageBuffer)
    {
        HpFreeAndNullWithTag(&gVeLoadedImageBuffer, IC_TAG_ALLOC);
    }

    gGuest.ProtectedEptIndex = INVALID_EPTP_INDEX;
    gVeModule.Protected = FALSE;
    gVeModule.ProtectionFlag = 0;

    gVeVeInitialized = gGuest.VeInitialized = FALSE;

    return status;
}


void
IntVeDumpVeInfoPages(
    void
    )
///
/// @brief Dumps the VE info pages on all VCPUs.
///
{
    if (!gVeVeInitialized || !gVeDeployed)
    {
        return;
    }

    for (DWORD cpu = 0; cpu < gGuest.CpuCount; cpu++)
    {
        IntVeDumpVeInfoPage(cpu);
        LOG("\n");
    }
}


void
IntVeDumpStats(
    void
    )
///
/// @brief Dump VE statistics.
///
{
    extern QWORD gEptEvents;
    DWORD i;
    QWORD totalVE = 0, mmFaults = 0, ignoredFaults = 0, igpw = 0, igpt = 0, igir = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_VE))
    {
        return;
    }

    if ((INVALID_EPTP_INDEX == gGuest.ProtectedEptIndex) || !gVeDeployed)
    {
        LOG("[VECORE] No #VE stats to dump!\n");
        return;
    }

    for (i = 0; i < gGuest.CpuCount; i++)
    {
        if (NULL != gGuest.VcpuArray[i].VeInfoPage)
        {
            LOG("[VECORE] [CPU %d] We've got %llu #VE events, %llu ignored "
                "(%llu page-walk, %llu irrelevant, %llu cache),  %f ticks/#VE\n",
                i,
                gGuest.VcpuArray[i].VeInfoPage->VeTotal, gGuest.VcpuArray[i].VeInfoPage->VeIgnoredTotal,
                gGuest.VcpuArray[i].VeInfoPage->VePageWalk, gGuest.VcpuArray[i].VeInfoPage->VeIgnoredIrrelevant,
                gGuest.VcpuArray[i].VeInfoPage->VeIgnoredCache,
                (double)gGuest.VcpuArray[i].VeInfoPage->TscTotal / (double)gGuest.VcpuArray[i].VeInfoPage->TscCount);

            totalVE += gGuest.VcpuArray[i].VeInfoPage->VeTotal;
            mmFaults += gGuest.VcpuArray[i].VeInfoPage->VeMm;
            ignoredFaults += gGuest.VcpuArray[i].VeInfoPage->VeIgnoredTotal;
            igpw += gGuest.VcpuArray[i].VeInfoPage->VePageWalk;
            igpt += gGuest.VcpuArray[i].VeInfoPage->VeIgnoredCache;
            igir += gGuest.VcpuArray[i].VeInfoPage->VeIgnoredIrrelevant;
        }
    }

    if (totalVE != 0)
    {
        LOG("[VECORE] Total EPT = %llu, non-#VE = %llu, #VE/PT = %llu, by MM = %llu, "
            "ignored = %llu - %f%% (page-walk = %llu, cache = %llu, irrel = %llu)\n",
            gEptEvents + totalVE, gEptEvents, totalVE, mmFaults, ignoredFaults,
            ignoredFaults * 100.0 / (double)totalVE, igpw, igpt, igir);
    }

    // INFO:
    // gEptEvents = number of clean EPT violations generated (does not include any kind of #VE)
    // totalFaults = total number of #VEs (by OS + by CPU page walk)
    // mmFaults = faults made explicitly by the OS memory manager
    // ignoredFaults = total number of ignored faults
    // igpw = ignored due to the page-walker
    // igpt = ignored due to the PT cache
    // igir = ignored due to irrelevant modification
    // igpw + igpt + igir = ignoredFaults
    // igpw + mmFaults = totalFaults
    // totalFaults - ignoredFaults = number of reported #VEs

    gEptEvents = 0;
}


void
IntVeHandleGuestResumeFromSleep(
    void
    )
///
/// @brief Simply set the VeAgentWaiting variable to true if VE is enabled.
///
{
    gGuest.VeAgentWaiting = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_VE);
}


INTSTATUS
IntVeUpdateCacheEntry(
    _In_ QWORD Address,
    _In_ BOOLEAN Monitored
    )
///
/// @brief Update an address inside the VE cache.
///
/// This function will map the cache page that should contain the entry. If the entry must be monitored (it has been
/// hooked), it will remove it from the cache. Otherwise, it will add it to the cache. Entries which are present
/// inside this cache are page-table entry which are not effectively monitored by Introcore. This means that writes
/// that take place on them can be safely emulated inside the guest without issuing a VMCALL to Introcore. The
/// Address is the address of the page-table entry, it is not a page-table address, as the cache works with entries,
/// not pages.
///
/// @param[in]  Address     Page table entry address to be added/removed from the cache.
/// @param[in]  Monitored   True if the entry must be monitored (remove it from the cache), false otherwise.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If VE is not initialized/the agent is not injected.
///
{
    INTSTATUS status;
    DWORD line, bucket, entry;

    // If #VE is not initialized, or it is not deployed, or it is pending unload, bail out.
    if (!gVeVeInitialized || !gVeDeployed || gVePendingUnload)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    // No cache initialized - bail out.
    if (gVeCache == 0)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    line = VE_CACHE_GET_LINE(Address);
    bucket = VE_CACHE_GET_BUCKET(Address);

    if (NULL == gVeCachePages[line].Page)
    {
        status = IntVirtMemMap(gVeCache + (QWORD)line * PAGE_SIZE, PAGE_SIZE,
                               gGuest.Mm.SystemCr3, 0, &gVeCachePages[line].Page);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    if (Monitored)
    {
        // Remove the entry from the cache.
        for (entry = 0; entry < VE_CACHE_ENTRIES; entry++)
        {
            if (gVeCachePages[line].Page->Entries[bucket][entry] == Address)
            {
                gVeCachePages[line].Page->Entries[bucket][entry] = 0;
                break;
            }
        }
    }
    else
    {
        BOOLEAN found = FALSE;

        // Add the entry to the cache. First make sure it isn't there already.
        for (entry = 0; entry < VE_CACHE_ENTRIES; entry++)
        {
            if (gVeCachePages[line].Page->Entries[bucket][entry] == Address)
            {
                found = TRUE;
                break;
            }
        }

        if (!found)
        {
            if (gVeCachePages[line].Indexes[bucket] == VE_CACHE_ENTRIES)
            {
                entry = __rdtsc() % VE_CACHE_ENTRIES;
            }
            else
            {
                entry = gVeCachePages[line].Indexes[bucket]++;
            }

            gVeCachePages[line].Page->Entries[bucket][entry] = Address;
        }
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}


BOOLEAN
IntVeIsAgentRemapped(
    _In_ QWORD Gla
    )
///
/// @brief Checks if a given guest linear address belongs to the VE agent.
///
/// The accessed Gla is in fact the address of a page-table entry. The algorithm in this function
/// converts the page-table entry address to the address of the page it maps, by shifting left
/// each self-map index entry.
///
/// @param[in]  Gla     The guest linear address to check.
///
/// @retval True if the Gla belongs to the VE agent, false otherwise.
///
{
    QWORD mapBase, mapSize;
    QWORD pml4i, pdpi, pdi, pti, pfi;

    // Check if the modified page-table entry remaps any portion of the #VE agent.
    pml4i = PML4_INDEX(Gla);
    pdpi = PDP_INDEX(Gla);
    pdi = PD_INDEX(Gla);
    pti = PT_INDEX(Gla);
    pfi = (Gla >> 3) & 0x1ff;
    mapBase = 0;
    mapSize = 8;

    // We assume the SelfMapIndex will not be 0.
    while (pml4i == gGuest.Mm.SelfMapIndex)
    {
        pml4i = pdpi;
        pdpi = pdi;
        pdi = pti;
        pti = pfi;
        pfi = 0;
        mapSize <<= 9;
    }

    mapBase = (pml4i << 39) | (pdpi << 30) | (pdi << 21) | (pti << 12);
    mapBase |= pml4i >= 0x100 ? 0xFFFF000000000000 : 0;

    if ((gVeDriverAddress >= mapBase && gVeDriverAddress < mapBase + mapSize) ||
        (mapBase >= gVeDriverAddress && mapBase < gVeDriverAddress + gVeDriverSize))
    {
        return TRUE;
    }

    return FALSE;
}
