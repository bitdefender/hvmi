/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "callbacks.h"
#include "decoder.h"
#include "gpacache.h"
#include "hook.h"
#include "hook_cr.h"
#include "hook_dtr.h"
#include "hook_msr.h"
#include "hook_xcr.h"
#include "memtables.h"
#include "ptfilter.h"
#include "rtlpvirtualunwind.h"
#include "swapmem.h"
#include "vecore.h"
#include "winprocesshp.h"
#include "winselfmap.h"
#include "wininfinityhook.h"
#include "exceptions.h"
#include "wincmdline.h"
#include "lixcmdline.h"
#include "scan_engines.h"
#include "wintoken.h"
#include "winsecdesc.h"
#include "winsud.h"

QWORD gEptEvents;
BOOLEAN gInjectVeLoader, gInjectVeUnloader;
BOOLEAN gLoadPtDriver, gUnloadPtDriver;

static BOOLEAN gForceActionOnBeta;


static BOOLEAN
IntValidateTranslation(
    _In_ PHOOK_GPA Hook
    )
///
/// @brief Checks if the given GPA hook points to a valid GVA hook with a correct translation.
///
/// This function will get the GVA hook (if any) pointing to the GPA hook, and it will attempt to translate the
/// virtual address to a physical address. Normally, the GPA the EPT violation just took place on and the GPA we
/// obtain after we translate the GVA should be the same. However, if there has been a translation error (for example,
/// somehow we missed a PTE write), the translated GPA could differ.
///
/// @param[in]  Hook    The GPA hook.
///
/// @returns TRUE of the translation is OK, FALSE otherwise.
///
{
    INTSTATUS status;
    PHOOK_HEADER header;
    PHOOK_GVA hookGva;
    VA_TRANSLATION tr;

    header = (PHOOK_HEADER)Hook->Header.ParentHook;

    if (header == NULL)
    {
        // No parent, this is a plain GPA hook (page table, most likely).
        return TRUE;
    }

    if (header->HookType != hookTypeGva)
    {
        // Not a GVA hook, there's nothing to translate.
        return TRUE;
    }

    hookGva = (PHOOK_GVA)header;

    // The CR3 used when the GVA hook was placed should be used for translation. This is needed because we may have
    // shared memory scenarios:
    // Process 1: GVA_1 via CR3_1 => GPA
    // Process 2: GVA_2 via CR3_2 => GPA
    // If we get an exit from Process 2, trying to translate GVA_1 through CR3_2 will fail, so use CR3_1, to make sure
    // it yields the expected GPA.
    status = IntTranslateVirtualAddressEx(hookGva->GvaPage, hookGva->PtsHook->Cr3, 0, &tr);
    if (!INT_SUCCESS(status) || 0 == (tr.Flags & PT_P))
    {
        // We couldn't translate this page - this may happen if the entry was invalidated due to a partial write
        // (on PAE x86), and in the meantime, an exit was triggered in that GPA.
        // In this case, we trigger the error if the PTS entry is NOT in a partial write state.
        if (hookGva->PtsHook->Parent->WriteState.WrittenMask == 0)
        {
            ERROR("[ERROR] Failed translating GVA 0x%016llx (reported GLA 0x%016llx, GPA 0x%016llx). "
                  "Int entry: 0x%016llx, Real entry: 0x%016llx, error: 0x%08x\n",
                  hookGva->GvaPage, gVcpu->Gla, gVcpu->Gpa,
                  hookGva->PtsHook->Parent->WriteState.IntEntry, tr.Flags, status);
            return FALSE;
        }

        // We can bail out now, both entries are invalid, which is good.
        return TRUE;
    }

    if ((tr.PhysicalAddress & PHYS_PAGE_MASK) != (gVcpu->Gpa & PHYS_PAGE_MASK))
    {
        // The translation succeeded, but we obtained a different GPA than the one we just got an exit for: this means
        // that the known GPA is outdated, and as such, we've probably missed a translation.
        ERROR("[ERROR] Translation mismatch for GVA 0x%016llx, translated GPA 0x%016llx "
              "(reported GLA 0x%016llx, GPA 0x%016llx)!\n",
              hookGva->GvaPage, tr.PhysicalAddress, gVcpu->Gla, gVcpu->Gpa);
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN
IntValidatePageRightsEx(
    _In_ QWORD LinearAddress,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Access
    )
///
/// @brief Check if the access rights for the provided PhysicalAddress are up-to-date in the EPT. This function will
/// get called oon each EPT violation.
///
/// Sometimes, setting the access rights may silently fail on some HVs. In order to address this, we implement
/// the following workaround: on EPT violations that are generated on a GPA which doesn't have any callback set,
/// we will re-set the access rights again, hopping that this time, no errors will take place in the HV.
///
/// @param[in]  LinearAddress       The accessed linear address.
/// @param[in]  PhysicalAddress     The accessed physical address.
/// @param[in]  Access              The access type.
///
/// @returns TRUE if the access rights are OK, FALSE if they were not OK, but they have been re-applied.
///
{
    INTSTATUS status;
    BYTE r, w, x;
    CHAR text[ND_MIN_BUF_SIZE];
    HOOK_EPT_ENTRY *eptEntry = IntHookGpaGetExistingEptEntry(PhysicalAddress);

    if (NULL != eptEntry)
    {
        // Read access, the page has at least one read hook.
        if (!!(Access & IG_EPT_HOOK_READ) && eptEntry->ReadCount != 0)
        {
            return TRUE;
        }

        // Write access, the page has at least one write hook.
        if (!!(Access & IG_EPT_HOOK_WRITE) && eptEntry->WriteCount != 0)
        {
            return TRUE;
        }

        // Execute access, the page has at least one execute hook.
        if (!!(Access & IG_EPT_HOOK_EXECUTE) && eptEntry->ExecuteCount != 0)
        {
            return TRUE;
        }
    }

    // Either we don't have an EPT entry at all (meaning that there are absolutely no EPT hooks on it), or the access
    // that generated the EPT violations does not coincide with a hook placed on the page.
    r = w = x = 0;

    status = IntGetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, &r, &w, &x);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
    }
    else
    {
        // We need this for logging purposes.
        NdToText(&gVcpu->Instruction, gVcpu->Regs.Rip, ND_MIN_BUF_SIZE, text);

        WARNING("[WARNING] GPA 0x%016llx, GLA 0x%016llx, was accessed with type %c%c%c, but no hooks exist on it: %c%c%c! "
                "CR3 0x%016llx RIP 0x%016llx %s\n",
                PhysicalAddress, LinearAddress,
                !!(Access & IG_EPT_HOOK_READ) ? 'R' : '-',
                !!(Access & IG_EPT_HOOK_WRITE) ? 'W' : '-',
                !!(Access & IG_EPT_HOOK_EXECUTE) ? 'X' : '-',
                r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-',
                gVcpu->Regs.Cr3, gVcpu->Regs.Rip, text);

        if (!!(Access & IG_EPT_HOOK_EXECUTE))
        {
            x = 1;
        }

        if (!!(Access & IG_EPT_HOOK_WRITE))
        {
            w = 1;
        }

        if (!!(Access & IG_EPT_HOOK_READ))
        {
            r = 1;
        }

        TRACE("[INFO] New access rights: %c%c%c\n", r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-');

        // This set has the role of fooling the integrator cache - if we set the exact same rights as last time,
        // the integrator may optimize it, by silently discarding the request. Therefore, we will set some different
        // rights before, in order to make sure we really end up calling the HV to modify the rights again.
        // Note that the 0, 0, 0 rights are correct - since there's at least one access type for which we didn't
        // find a hook, this means there is at least on access right present for the page, so at least one of the
        // R, W or X is 1. Therefore, the RWX == 000 request will most certainly be different than the current
        // actual rights.
        status = IntSetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, 0, 0, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
        }

        // Now the actual RWX rights.
        status = IntSetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, r, w, x);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
        }

        IntFlushEPTPermissions();
    }

    return FALSE;
}


static void
IntValidatePageRights(
    _In_ QWORD LinearAddress,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Access
    )
///
/// @brief Check if the access rights for the provided PhysicalAddress are up-to-date in the EPT. This function will
/// get called only if the page wasn't hooked.
///
/// Sometimes, setting the access rights may silently fail on some HVs. In order to address this, we implement
/// the following workaround: on EPT violations that are generated on a GPA which doesn't have any callback set,
/// we will re-set the access rights again, hopping that this time, no errors will take place in the HV.
///
/// @param[in]  LinearAddress       The accessed linear address.
/// @param[in]  PhysicalAddress     The accessed physical address.
/// @param[in]  Access              The access type.
///
{
    INTSTATUS status;
    BYTE r, w, x;
    CHAR text[ND_MIN_BUF_SIZE];

    // We need this for logging purposes.
    NdToText(&gVcpu->Instruction, gVcpu->Regs.Rip, ND_MIN_BUF_SIZE, text);

    r = w = x = 0;

    WARNING("[WARNING] GPA 0x%016llx, GLA 0x%016llx, was accessed with type %d, but no hooks exist on it! "
            "CR3 0x%016llx RIP 0x%016llx %s\n",
            PhysicalAddress, LinearAddress, Access, gVcpu->Regs.Cr3, gVcpu->Regs.Rip, text);

    status = IntGetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, &r, &w, &x);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
    }
    else
    {
        TRACE("[INFO] Old access rights: %c%c%c\n", r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-');

        if (!!(Access & IG_EPT_HOOK_EXECUTE))
        {
            x = 1;
        }

        if (!!(Access & IG_EPT_HOOK_WRITE))
        {
            w = 1;
        }

        if (!!(Access & IG_EPT_HOOK_READ))
        {
            r = 1;
        }

        TRACE("[INFO] New access rights: %c%c%c\n", r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-');

        // This set has the role of fooling the integrator cache - if we set the exact same rights as last time,
        // the integrator may optimize it, by silently discarding the request. Therefore, we will set some different
        // rights before, in order to make sure we really end up calling the HV to modify the rights again.
        // Note that the 0, 0, 0 rights are correct - since there's at least one access type for which we didn't
        // find a hook, this means there is at least on access right present for the page, so at least one of the
        // R, W or X is 1. Therefore, the RWX == 000 request will most certainly be different than the current
        // actual rights.
        status = IntSetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, 0, 0, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
        }

        // Now the actual RWX rights.
        status = IntSetEPTPageProtection(gVcpu->EptpIndex, PhysicalAddress, r, w, x);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for 0x%016llx: 0x%08x\n", PhysicalAddress, status);
        }

        IntFlushEPTPermissions();
    }
}


static INTSTATUS
IntHandleMemAccess(
    _In_ QWORD LinearAddress,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ BOOLEAN *CallbackFound,
    _Inout_ BOOLEAN *PageHooked,
    _In_ BOOLEAN ProbeOnly,
    _In_ IG_EPT_ACCESS AccessType
    )
///
/// @brief Handle a memory access to a guest linear address.
///
/// This function handles one GLA access (execute, read, write or read-write). The access can be combined (for example,
/// read-write). The function will iterate the list of registered callbacks for the PhysicalAddress the given
/// LinearAddress translates to, and it will call each registered callback. The actions returned by the callback will
/// be combined (the numerically higher action will be kept) and returned. Each access will be handled individually;
/// for example, if the AccessType is RWX, the function will first handle the execute access, followed by the
/// read access, followed finally by the write access. For read accesses which do not have a registered callback,
/// the mem-tables and the RtlpVirtualUnwind optimizations will be invoked, to see if we can instrument the
/// instruction, for better performance.
/// NOTE: If no callback is found, the default action is #introGuestAllowed.
/// NOTE: This function may be called for PhysicalAddress values for which an EPT violation has not been generated.
/// This happens because when handling an instruction, Introcore will call this function for every accessed linear
/// address, even for those for which an EPT violation may never be generated.
///
/// @param[in]  LinearAddress       The guest linear address accessed.
/// @param[in]  PhysicalAddress     The guest physical address accessed.
/// @param[in]  Length              The size of the access. For execute accesses, this is the length of the instruction
///                                 For read/write accesses, this is the size of the access.
/// @param[out] Action              The final action returned by the invoked callbacks.
/// @param[out] CallbackFound       Set to true if at least one callback is found for the provided address.
/// @param[out] PageHooked          Set to true if the page is indeed hooked.
/// @param[in]  ProbeOnly           If set, simply check if there is at least a callback for the address. If this
///                                 is set, no callbacks will be invoked, as the function will return as soon as
///                                 at find the first registered callback.
/// @param[in]  AccessType          Access type. Can be a combination of #IG_EPT_HOOK_EXECUTE, #IG_EPT_HOOK_READ and
///                                 #IG_EPT_HOOK_WRITE.
///
/// @retval #INT_STATUS_SUCCESS On success. This does not necessarily mean that a callback was found!
/// @retval #INT_STATUS_NOT_INITIALIZED If the hooks system is not initialized.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    DWORD hid;
    QWORD physPage;
    LIST_ENTRY *hooks, *list;
    INTRO_ACTION action, finalAction;
    IG_EPT_ACCESS access;
    STAT_ID stat, statRip;

    action = finalAction = introGuestAllowed;
    access = AccessType;

    if (NULL == gHooks)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    gVcpu->Gpa = PhysicalAddress;
    gVcpu->Gla = LinearAddress;
    gVcpu->AccessSize = Length;

    // Assume no callback handled this access.
    *CallbackFound = FALSE;
    *PageHooked = FALSE;

    hid = GPA_HOOK_ID(PhysicalAddress);

    physPage = PhysicalAddress & PHYS_PAGE_MASK;

handle_next_access:
    hooks = NULL;

    if (AccessType & IG_EPT_HOOK_EXECUTE)
    {
        hooks = &gHooks->GpaHooks.GpaHooksExecute[hid];
        AccessType &= ~IG_EPT_HOOK_EXECUTE;
        stat = statsEptExecute;
    }
    else if (AccessType & IG_EPT_HOOK_READ)
    {
        hooks = &gHooks->GpaHooks.GpaHooksRead[hid];
        AccessType &= ~IG_EPT_HOOK_READ;
        stat = statsEptRead;
    }
    else if (AccessType & IG_EPT_HOOK_WRITE)
    {
        hooks = &gHooks->GpaHooks.GpaHooksWrite[hid];
        AccessType &= ~IG_EPT_HOOK_WRITE;
        stat = statsEptWrite;
    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_8;
    }

    if (hooks == NULL)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (0 != (gVcpu->Regs.Rip & (gGuest.Guest64 ? 0x8000000000000000 : 0x80000000)))
    {
        statRip = statsEptKernel;
    }
    else
    {
        statRip = statsEptUser;
    }

    STATS_ENTER(stat);
    STATS_ENTER(statRip);
    STATS_ENTER(statsEptLookup);

    // Xen handles events single-threaded. There's no point in complicating the event handler with a shared lock.
    // This way, we can add new hooks from existing hooks (no problem if we add hook while we iterate the list).
    // However, no hooks can be removed from the list - it's safe to iterate the list while new hooks may be
    // added, since we know for sure no entry will become invalid while we have gLock acquired.

    // Try to find a suitable hook to call
    list = hooks->Flink;
    while (list != hooks)
    {
        PHOOK_GPA pHook = CONTAINING_RECORD(list, HOOK_GPA, Link);

        if (pHook->GpaPage == physPage)
        {
            *PageHooked = TRUE;

            // Check if write took place outside this protected region
            if ((pHook->GpaPage + pHook->Offset >= PhysicalAddress + Length) ||
                (pHook->GpaPage + pHook->Offset + pHook->Length <= PhysicalAddress))
            {
                goto _hook_continue;
            }

            if (0 == (pHook->Header.Flags & (HOOK_FLG_REMOVE | HOOK_FLG_DISABLED)))
            {
#ifdef CFG_DEBUG_EPT_VIOLATIONS
                TRACE("[DEBUG] Calling EPT handler for GPA 0x%016llx, hook address: 0x%016llx, callback 0x%016llx\n",
                      PhysicalAddress, pHook, pHook->Callback);
#endif

#ifdef CHECK_PAGE_RIGHTS
                if (!IntValidateTranslation(pHook))
                {
                    ERROR("[ERROR] IntValidateTranslation failed: GLA 0x%016llx, GPA 0x%016llx!\n",
                          LinearAddress, PhysicalAddress);
                    IntHookPtsDump();
                }
#endif

                // Indicate that we've found a callback.
                *CallbackFound = TRUE;

                // If we don't want to actually handle the access, bail out now and don't invoke any handlers.
                if (ProbeOnly)
                {
                    AccessType = 0; // Stop access handling.
                    status = INT_STATUS_SUCCESS;
                    break;
                }

                // Pre-process all the PT writes here, before calling any callback. We will then cache the old & new
                // values.
                // Note: we do this only if we find a callback; otherwise, we let the hypervisor emulate the access.
                // If we don't have at least a callback registered for a page, there's no way to know if that page is
                // a page table or not.
                if ((pHook->Header.EptHookType == IG_EPT_HOOK_WRITE) &&
                    !!(pHook->Header.Flags & HOOK_PAGE_TABLE_FLAGS) &&
                    !gVcpu->PtEmuBuffer.Valid)
                {
                    QWORD oldValue, newValue;

                    status = IntHookPtwEmulateWrite(PhysicalAddress);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntHookPtwEmulateWrite failed: 0x%08x\n", status);
                        IntBugCheck();
                    }

                    oldValue = gVcpu->PtEmuBuffer.Old;
                    newValue = gVcpu->PtEmuBuffer.New;

                    // If the write didn't touch any relevant bits, we can bail out right now. There's no point in
                    // calling the callback, since it will bail out itself.
                    if (gVcpu->PtEmuBuffer.Valid && !gVcpu->PtEmuBuffer.Partial &&
                        (((oldValue & HOOK_PTS_MONITORED_BITS) == (newValue & HOOK_PTS_MONITORED_BITS)) ||
                         (0 == ((oldValue & PT_P) + (newValue & PT_P)))))
                    {
                        status = INT_STATUS_SUCCESS;
                        break;
                    }
                }

                STATS_ENTER(statsEptHandle);

                status = (pHook->Callback)(pHook->Header.Context, pHook, PhysicalAddress, &action);

                STATS_EXIT(statsEptHandle);

                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] EPT callback failed: 0x%08x\n", status);

                    goto _hook_continue;
                }

                // Check if the callback requested to be removed.
                if ((INT_STATUS_REMOVE_HOOK_ON_RET == status) || (INT_STATUS_REMOVE_AND_SKIP == status))
                {
                    INTSTATUS status2;

                    status2 = IntHookRemoveChain(pHook);
                    if (!INT_SUCCESS(status2))
                    {
                        ERROR("[ERROR] IntHookRemoveChain failed: 0x%08x\n", status2);
                    }
                }

                // Check if the returned action should be forced on beta.
                if (INT_STATUS_FORCE_ACTION_ON_BETA == status)
                {
                    gForceActionOnBeta = TRUE;
                }

                // The verdicts priorities is the following:
                // - allow - smallest priority; default for all callbacks that don't have security logic.
                // - block - the action has been blocked by the introspection logic
                // - allow virtual - the action has been emulated by the introspection logic
                // - allow patched - the actual accessed data has been patched by the introspection logic
                // - ignore - ignore and allow the action
                // - retry - highest priority; the instruction will be literally re-executed (without modifying EPT)
                finalAction = MAX(action, finalAction);

                // Check if the callback requested skipping all other callbacks.
                if ((INT_STATUS_SKIP_OTHER_CALLBACKS == status) || (INT_STATUS_REMOVE_AND_SKIP == status))
                {
                    break;
                }
            }
        }

_hook_continue:
        // We must update the list entry after the callback is called, because new hooks may be added from existing
        // callbacks. This way, we ensure a deterministic behavior, where new hooks added for the currently-faulted
        // page will all be called.
        list = list->Flink;
    }

    STATS_EXIT(statsEptLookup);
    STATS_EXIT(statRip);
    STATS_EXIT(stat);

    if (0 != AccessType)
    {
        goto handle_next_access;
    }

    // Only read accesses
    if (!(*CallbackFound) && *PageHooked && (access == IG_EPT_HOOK_READ))
    {
        status = IntMtblCheckAccess();
        if (INT_STATUS_INSTRUCTION_PATCHED == status)
        {
            // If we successfully patched the instruction, retry it right now.
            finalAction = introGuestRetry;
        }

        IntRtlpVirtualUnwindCheckAccess();
    }

///#ifdef CHECK_PAGE_RIGHTS
    // Handle special cases where permission set may have failed silently, leaving a page with no registered hooks,
    // but with altered EPT permissions. Note that we are interested only in the exit GPA; in reality, the
    // mem access handler may be called for more addresses - practically, for each individual address accessed
    // by the instruction. Most of the times, those additional addresses point inside pages that are not hooked,
    // so there's no need to restore the rights for them. Also, no need to do this if PT filtering is enabled, and we
    // are in the context of a PT write raised from the agent, as in that case, the page-tables will be RWX by default.
    // Furthermore, avoid calling the validation routine if the accessed linear address is the same as the page
    // containing the RIP: if an execution exit was previously generated, we may be in a single-step/re-execution
    // context inside the HV, so calling SetEPTPageProtection now may break whatever access rights the HV placed in
    // order to properly re-execute the instruction.
    if (!*PageHooked &&                             // The page must not be hooked.
        (PhysicalAddress == gVcpu->ExitGpa) &&      // The accessed GPA must be the one the exit was triggered on.
        (LinearAddress == gVcpu->ExitGla) &&        // The accessed GLA must be the one the exit was triggered on.
        (access == gVcpu->ExitAccess) &&            // The access type must be the one generated at exit.
        ((gVcpu->Regs.Rip & PAGE_MASK) != (LinearAddress & PAGE_MASK)) && // Not the same page with the RIP
        !gVcpu->PtContext)                          // Not in PT context, as page tables are writable
    {
        IntValidatePageRights(LinearAddress, PhysicalAddress, access);
    }
///#endif

    *Action = MAX(*Action, finalAction);

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntHandleFetchRetryOnPageBoundary(
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle instruction fetch at page boundary, if an EPT execute violation has been generated.
///
/// Special handling for introGuestRetry on EPT exec violations. We may request a retry when we cannot fetch the RIP,
/// for example. Sometimes, the instruction may be situated at a page boundary and be contained inside both pages.
/// In this case, if at least the first page is exec hooked and the second one is not present, we will induce an
/// infinite loop by requesting introGuestRetry, because the PF on the second page will never be triggered since the
/// EPT violation on the first one will always take place first. In this case, we will manually inject the PF on
/// the second page.
///
/// @param[in]  CpuNumber   VCPU number.
///
/// @returns True if a PF has been injected inside the guest, false otherwise.
///
{
    INSTRUX instrux;
    BYTE code[16];
    DWORD cbread = 0, csType, ring;
    QWORD rip = gVcpu->Regs.Rip;
    QWORD cr3 = gVcpu->Regs.Cr3;

    // Optimistically read up to 16 bytes starting with the current RIP. This will be more than enough, and it may
    // span the next page (even if the instruction doesn't), but in this case, the decode will simply succeed.
    IntVirtMemRead(rip, sizeof(code), cr3, code, &cbread);
    if (cbread > 0 && cbread < 16)
    {
        INTSTATUS status;
        NDSTATUS ndstatus;

        // Get the current mode (again), as it's needed for the disassembler.
        status = IntGetCurrentMode(CpuNumber, &csType);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
            return FALSE;
        }

        // Get the current ring. It's needed for the US flag inside the #PF error code.
        status = IntGetCurrentRing(CpuNumber, &ring);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
            return FALSE;
        }

        // Attempt to decode whatever instruction lies at RIP. There are two main possibilities:
        // 1. The decode succeeds. This means that one or two pages that contain the instruction have already been
        //    swapped in, and there's nothing more we need to do. This is less likely if we get here.
        // 2. The decode fails because the buffer is too small. This means the instruction spills in the second page,
        //    which is still swapped out. We can inject a #PF on it, and retry. Not injecting a #PF on the second page
        //    would trigger an infinite loop, because the first page would continue generating EPT violations BEFORE the
        //    second page is accessed and gets to generate a #PF.
        ndstatus = NdDecodeEx(&instrux, code, cbread,
                                       (csType == IG_CS_TYPE_64B) ? ND_CODE_64 : ND_CODE_32,
                                       (csType == IG_CS_TYPE_64B) ? ND_DATA_64 : ND_DATA_32);
        if (ND_STATUS_BUFFER_TOO_SMALL == ndstatus)
        {
            // We read at least one byte from the page end, but the decode still failed with ND_STATUS_BUFFER_TOO_SMALL.
            // This means only one thing: the instruction spills inside the next page, and the next page is not present.
            // Page fault error code: instruction fetch from user/supervisor mode.
            DWORD pfec = PFEC_ID | (ring == IG_CS_RING_3 ? PFEC_US : 0);

            status = IntInjectExceptionInGuest(VECTOR_PF, (rip + PAGE_SIZE) & PAGE_MASK, pfec, CpuNumber);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntInjectExceptionInGuest failed: 0x%08x\n", status);
                return FALSE;
            }

            TRACE("[INFO] Fetch retry at GLA 0x%016llx, CR3 0x%016llx\n", rip, cr3);

            return TRUE;
        }

        // All other statuses can fall through, as we cannot (and shouldn't) inject a #PF for them.
    }

    // Nothing read, or everything is successful - nothing we should do.
    return FALSE;
}


static BOOLEAN
IntHandleCowOnPage(
    _In_ QWORD Gla,
    _In_ DWORD CpuNumber,
    _In_ BYTE AccessType
    )
///
/// @brief Handle copy-on-write on a page.
///
/// This function handles copy-on-write events on a given guest linear address. This is needed because of an
/// emulator flaw in Xen: a CMPXCHG instruction at a page-boundary would be emulated badly by copying the first
/// chunk of data inside the first page, then injection a PF for the second page, if it isn't writable. When
/// re-executing the CMPXCHG after the fault is handled, the memory value would be different, and the instruction
/// would not execute correctly (since the first page has already been written).
/// Check if this is a write access, inside user-mode, on a non-present or non-writable page, and inject a PF if
/// needed.
///
/// @param[in]  Gla         The accessed guest linear address.
/// @param[in]  CpuNumber   The VCPU number.
/// @param[in]  AccessType  Access type.
///
/// @returns True if a PF has been injected due to CoW, false otherwise.
///
{
    INTSTATUS status;
    QWORD cr3 = gVcpu->Regs.Cr3;
    VA_TRANSLATION tr;
    DWORD ring;

    if (0 == (ND_ACCESS_ANY_WRITE & AccessType))
    {
        return FALSE;
    }

    status = IntGetCurrentRing(CpuNumber, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return FALSE;
    }

    if (IG_CS_RING_3 != ring)
    {
        return FALSE;
    }

    status = IntTranslateVirtualAddressEx(Gla, cr3, TRFLG_NONE, &tr);
    if (!INT_SUCCESS(status) &&
        (INT_STATUS_NO_MAPPING_STRUCTURES != status) &&
        (INT_STATUS_PAGE_NOT_PRESENT != status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return FALSE;
    }

    if ((INT_STATUS_NO_MAPPING_STRUCTURES == status) ||
        (INT_STATUS_PAGE_NOT_PRESENT == status) ||
        (0 == (tr.Flags & PT_P)) ||
        !tr.IsWritable)
    {
        DWORD pfec;

        // User-mode fault, write access, page may or may not be present.
        if ((INT_STATUS_NO_MAPPING_STRUCTURES == status) ||
            (INT_STATUS_PAGE_NOT_PRESENT == status) ||
            (0 == (tr.Flags & PT_P)))
        {
            pfec = 0;
        }
        else
        {
            pfec = PFEC_P;
        }

        pfec |= PFEC_US | PFEC_RW;

        status = IntInjectExceptionInGuest(VECTOR_PF, Gla, pfec, CpuNumber);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntInjectExceptionInGuest failed: 0x%08x\n", status);
            return FALSE;
        }

        TRACE("[INFO] Xen workaround at GLA 0x%016llx/0x%016llx, CR3 0x%016llx\n", Gla, Gla, cr3);

        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
IntHandlePageBoundaryCow(
    _In_ QWORD Gla,
    _In_ DWORD AccessSize,
    _In_ BYTE AccessType,
    _In_ DWORD CpuNumber
    )
///
/// @brief Check if we have a copy-on-write condition at a page boundary.
///
/// Check if the accessed gla spans inside two pages, and it it is the case, call the CoW handler.
///
/// @param[in]  Gla         The accessed guest linear address.
/// @param[in]  AccessSize  The access size, in bytes.
/// @param[in]  AccessType  Access type (should be read-write or write).
/// @param[in]  CpuNumber   VCPU number.
///
/// @returns True if a PF has been injected due to CoW, false otherwise.
///
{
    QWORD secpg;

    if ((Gla & 0xFFF) <= ((Gla + AccessSize - 1) & 0xFFF))
    {
        return FALSE;
    }

    secpg = (Gla + AccessSize - 1) & PAGE_MASK;

    return IntHandleCowOnPage(secpg, CpuNumber, AccessType);
}


INTSTATUS
IntHandleEptViolation(
    _In_ void *GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_ QWORD LinearAddress,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action,
    _In_ IG_EPT_ACCESS AccessType
    )
///
/// @brief Handle an EPT violation.
///
/// This callback is called by the HV/integrator whenever an EPT violation takes place. Introcore will handle
/// the event by calling registered callbacks for the accessed memory area. Note that Introcore will also call
/// the callbacks for other linear addresses that may be accessed by the instruction. Upon return, it has to
/// return an action to the integrator.
/// The main steps taken by this function are:
/// 1. Decode the instruction that triggered the EPT violation;
/// 2. Handle PT filter or mem-table instructions that triggered an exit after being handled by another VCPU;
/// 3. Check if the EPT violation took place inside the protected EPT view; if so, call the appropriate handler;
/// 4. Handle the execute EPT violation, if it's the case;
/// 5. Decode all addresses the instruction accesses, and, for each decoded linear address, translate it to
/// a physical address, and call the #IntHandleMemAccess function (note that the translation will not be done
/// if the accessed linear address is the same as LinearAddress);
/// 6. Handle REP instructions: if a REP prefixed instruction touches a region of memory which is hooked, disable
/// REP optimizations, and re-execute that instruction step by step;
/// 7. Handle read emulation. If we have reads made by the patch-guard inside hidden memory areas, return the
/// original data;
/// 8. Handle x86 PAE page table writes. If one 4 bytes piece from an 8 bytes page-table entry is written,
/// search for the instruction which writes the second 4 bytes piece, and emulate that too;
/// 9. Handle Copy-on-Write at page boundary.
/// NOTE: A good security measure is to not handle an EPT violation if the instruction that triggered it is not
/// cached. The reasoning behind this is TOCTOU: while we disassemble & analyze the instruction that triggered
/// the fault, an attacker may replace that instruction with a malicious one, which may get emulated once
/// Introcore decides that the action was legitimate. Therefore, if an EPT violation is generated from an
/// instruction that is not cached, simply cache the instruction, and re-execute it. The second time the EPT
/// violation takes place, the instruction will be cached, and an attacker won't be able to replace it inside
/// guest memory, since a cached instruction means that the page it lies in is marked non-writable inside EPT.
/// NOTE: The reason why we may call the memory access function for linear addresses for which no EPT violation
/// has been generated is because we must inspect each address accessed by the instruction in order to conclude
/// that it is legitimate. For example, let's say the instruction "PUSH [rax]" is executed, and it triggers
/// a read EPT violation on the memory pointed by "rax". Introcore may conclude that this is legitimate, that
/// memory can be read, and the instruction can be emulated. However, the instruction also writes to the
/// memory pointed by "rsp" (the stack), which may also be hooked against writes! However, because Introcore
/// allowed the instruction to be emulated, this stack write would no longer generate an EPT violation, and
/// protection may be bypassed. Therefore, in order to deem an instruction safe to be emulated, we analyze
/// every address accessed by the instruction.
///
/// @param[in]  GuestHandle         A handle to the guest that generated the EPT violation.
/// @param[in]  PhysicalAddress     Accessed guest physical address.
/// @param[in]  Length              Access size. Note that this parameter is reserved for future use, as the HV
///                                 does not decode (and the CPU does not provide) the access size.
/// @param[in]  LinearAddress       The accessed guest linear address.
/// @param[in]  CpuNumber           VCPU number.
/// @param[out] Action              Will contain, upon successful return, the action to be taken fro the access.
/// @param[in]  AccessType          Access type: #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE & #IG_EPT_HOOK_EXECUTE.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_FORCE_ACTION_ON_BETA Force the introGuestNotAllowed, even in beta mode. This ensures that
///                                         our hooks don't get overwritten.
/// @retval #INT_STATUS_FATAL_ERROR A fatal error occurred, and the integrator should unload Introcore.
///
{
    INTSTATUS status;
    INTRO_ACTION action;
    DWORD glacount, glaidx, pgcnt, pgidx, tsize, asize;
    QWORD tgla;
    BOOLEAN cbkFound, probe, pageHooked, cacheuse, cachehit, cacheadd, fetchfail;
    IG_EPT_ACCESS access;
#define MAX_GLAS 32
    MEMADDR glas[MAX_GLAS] = {0};
    struct
    {
        QWORD gla, gpa;
        DWORD size;
    } pages[2];

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_7;
    }

    action = introGuestAllowed;
    glacount = glaidx = pgcnt = pgidx = tsize = 0;
    probe = FALSE;
    cbkFound = FALSE;
    pageHooked = FALSE;
    cachehit = FALSE;
    cacheadd = FALSE;
    fetchfail = FALSE;

    *Action = introGuestAllowed;

    IntSpinLockAcquire(gLock);

    gEptEvents++;

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

#ifdef CFG_DEBUG_EPT_VIOLATIONS
    TRACE("[DEBUG] EPT violation for GPA 0x%016llx, GLA 0x%016llx, on CPU %d, type %d\n",
          PhysicalAddress, LinearAddress, CpuNumber, AccessType);
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] An EPT exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_5;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_EPT_VIOLATION;

    STATS_ENTER(statsEptViolation);

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_stop_count;
    }

    // Get the EPT index in order to determine whether we are in protected view or not.
    status = IntGetCurrentEptIndex(CpuNumber, &gVcpu->EptpIndex);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentEptIndex failed: 0x%08x\n", status);
        goto _exit_stop_count;
    }

    STATS_ENTER(statsEptDecode);

    cacheuse = ((gGuest.Mm.SystemCr3 != 0) && (AccessType != IG_EPT_HOOK_EXECUTE));

    status = IntDecDecodeInstructionAtRipWithCache(gGuest.InstructionCache,
                                                   CpuNumber,
                                                   &gVcpu->Regs,
                                                   &gVcpu->Instruction,
                                                   cacheuse ? 0 : DEC_OPT_NO_CACHE,
                                                   &cachehit, &cacheadd);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        TRACE("[INFO] The page containing the RIP %llx has been swapped out; will retry the instruction.\n",
              gVcpu->Regs.Cr3);

        action = introGuestRetry;
        fetchfail = TRUE;
        status = INT_STATUS_SUCCESS;
        goto _exit_pre_ret;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeInstructionAtRipWithCache failed: 0x%08x\n", status);
        goto _exit_stop_count;
    }

    STATS_EXIT(statsEptDecode);

    // We get an exit from the RIP that was allowed to execute, bu this time it's not an exec violation - this means
    // that instruction accessed another hooked page, so right now we're in single-step/re-execute context in the HV.
    if (gVcpu->AllowOnExec && (gVcpu->AllowOnExecRip == gVcpu->Regs.Rip) &&
        (gVcpu->AllowOnExecGpa != PhysicalAddress || (IG_EPT_HOOK_EXECUTE != AccessType)))
    {
        LOG("[WARNING] We are in reexecute context: RIP = 0x%016llx, GLA = 0x%016llx, GPA = 0x%016llx, ACC = %d\n",
            gVcpu->Regs.Rip, LinearAddress, PhysicalAddress, AccessType);
        gVcpu->SingleStep = TRUE;
    }
    else
    {
        gVcpu->SingleStep = FALSE;
        gVcpu->AllowOnExec = FALSE;
        gVcpu->AllowOnExecRip = 0;
        gVcpu->AllowOnExecGpa = 0;
    }

#ifdef CHECK_PAGE_RIGHTS
    if (!gVcpu->SingleStep && !IntValidatePageRightsEx(LinearAddress, PhysicalAddress, AccessType))
    {
        action = introGuestRetry;
        goto _exit_pre_ret;
    }
#endif

    // If we use the instruction cache, and we could add the instruction on the cache but it wasn't previously cached
    // then retry the instruction, in order to mitigate ToCvsToS attacks.
    if (cacheuse && cacheadd && !cachehit)
    {
        action = introGuestRetry;
        goto _exit_pre_ret;
    }

_process_again:
    // Fill in the original access information, as generated at VM exit.
    gVcpu->ExitGpa = PhysicalAddress;
    gVcpu->ExitGla = LinearAddress;
    gVcpu->ExitAccess = AccessType;

    // Make sure we reset this on each EPT violation.
    gVcpu->PatchBuffer.Valid = FALSE;
    gVcpu->PtWriteCache.Valid = FALSE;
    gVcpu->PtEmuBuffer.Valid = FALSE;
    gVcpu->PtEmuBuffer.Emulated = FALSE;
    gVcpu->PtEmuBuffer.Partial = FALSE;


    if ((ND_ACCESS_READ | ND_ACCESS_WRITE) == (gVcpu->Instruction.MemoryAccess & (ND_ACCESS_READ | ND_ACCESS_WRITE)))
    {
        STATS_ENTER(statsEptRMW);
        STATS_EXIT(statsEptRMW);
    }


    // Sometimes, we end up modifying instructions inside the guest memory:
    // 1. Instructions that access a switch - case branch table (memtable instructions)
    // 2. Instructions that access a PT, when we deploy the PT filtering agent
    // In these cases, we may get an exit before the instruction is modified, but by the time we get here, another
    // CPU got to modify that instruction. Therefore, we'll have an EPT violation with a peculiar instruction, such
    // as a JMP, INT3 or INT 20. It's easy to handle them - simply re-enter the guest and let the new course of action
    // take place. However, we must ensure that we avoid hangs, in case one of these instructions legitimately
    // causes a read/write EPT violation.
    // For JMP and INT 20 on memtables, the treatment is simple, since there will be no match inside the hooks.
    if (((gVcpu->Instruction.Instruction == ND_INS_INT3) ||
         ((gVcpu->Instruction.Instruction == ND_INS_INT) && (gVcpu->Instruction.Immediate1 == 20))) &&
        (IG_EPT_HOOK_EXECUTE != AccessType) && (INT_STATUS_NO_DETOUR_EMU == IntPtiHandleInt3()))
    {
        TRACE("[INFO] The instruction at RIP seems to have been modified, will retry the instruction.\n");
        action = introGuestRetry;
        status = INT_STATUS_SUCCESS;
        goto _exit_pre_ret;
    }

    // If this instruction is a JMP or a INT 20, check if it was a replace memtable instruction, in which case we
    // can safely retry it.
    if (((gVcpu->Instruction.Instruction == ND_INS_JMPNR) ||
         ((gVcpu->Instruction.Instruction == ND_INS_INT) && (gVcpu->Instruction.Immediate1 == 20))) &&
        (IG_EPT_HOOK_EXECUTE != AccessType) && (IntMtblInsRelocated(gVcpu->Regs.Rip)))
    {
        TRACE("[INFO] The instruction at RIP seems to have been relocated, will retry the instruction.\n");
        action = introGuestRetry;
        status = INT_STATUS_SUCCESS;
        goto _exit_pre_ret;
    }

    // Xen always sets the R flag, for every W violation. See if the instruction indeed does read access to the
    // memory, and clear the R flag if it doesn't.
    if (0 == (gVcpu->Instruction.MemoryAccess & ND_ACCESS_ANY_READ))
    {
        AccessType &= ~IG_EPT_HOOK_READ;
    }

    // Usually, only one GLA will be accessed with a simple Write instruction. In rare cases, however, any combination
    // of the following may take place:
    // - multiple GLAs accessed (such as PUSH [mem], POP [mem], MOVSD, etc.).
    // - RMW or RW access (XOR [mem], r, ADD [mem], r, MOVSD, etc.)
    // - page boundary accesses

    if (gVcpu->Instruction.IsRepeated)
    {
        // If the REP optimizations are disabled, we can handle the access. Otherwise, we will probe the entire access.
        probe = (0 == gGuest.RepOptsDisableCount);
    }
    else
    {
        // No REP instruction, check if we can re-enable the REP optimizations.
        if (gVcpu->RepOptDisabled)
        {
            gVcpu->RepOptDisabled = FALSE;

            if (0 == --gGuest.RepOptsDisableCount)
            {
                IntToggleRepOptimization(TRUE);
            }
        }
    }

    // Check if we are in protected EPT, if so, send an alert.
    if (gVcpu->EptpIndex == gGuest.ProtectedEptIndex)
    {
        // Make sure we have the right thing in CurrVcpu
        gVcpu->Gla = LinearAddress;
        gVcpu->Gpa = PhysicalAddress;

        status = IntVeHandleEPTViolationInProtectedView(AccessType, &action);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeHandleEPTViolationInProtectedView failed: 0x%08x\n", status);
        }

        goto done_handling_instruction;
    }

    // Handle execution violations. These are special, since an execution fault will be signaled during the fetch phase,
    // so no other read or write fault will be reported.
    if (AccessType & IG_EPT_HOOK_EXECUTE)
    {
        // Handle the execute fault, if any. Note that there's no need to handle split-page access for execution faults.
        status = IntHandleMemAccess(LinearAddress, PhysicalAddress, gVcpu->Instruction.Length,
                                    &action, &cbkFound, &pageHooked, FALSE, IG_EPT_HOOK_EXECUTE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHandleMemAccess failed for 0x%016llx/0x%016llx with size 0x%x for type %d: %08x\n",
                  PhysicalAddress, LinearAddress, Length, AccessType, status);
        }

        // If the restriction has been removed, we can bail out, No need to check other accesses, as they will cause
        // fault upon retrying the instruction.
        if (introGuestRetry == action)
        {
            goto done_handling_instruction;
        }
    }

    // Decode the number of memory locations accessed.
    status = IntDecGetAccessedMemCount(&gVcpu->Instruction, &glacount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecGetAccessedMemCount failed: 0x%x\n", status);
        status = INT_STATUS_NOT_SUPPORTED;
        goto _exit_stop_count;
    }

    // Handle memory accesses.
    if (glacount == 0)
    {
        // No access - we can leave now.
        goto done_handling_instruction;
    }
    else if ((glacount == 1) && !(AccessType & IG_EPT_HOOK_EXECUTE))
    {
        /// NOTE: The instruction may be modified after the fault is triggered. Therefore, we may process the
        /// GLA/GPA the fault took place at, but the instruction may encode a different address.

        // A single address is accessed, this is easy to handle. The accessed GLA must be the provided LinearAddress.
        glas[0].Gla = LinearAddress;
        // Use the access as indicated by the Instrux - Xen always send RW access for every W fault.
        glas[0].Access = AccessType;

        status = IntDecDecodeAccessSize(&gVcpu->Instruction,
                                        &gVcpu->Regs, LinearAddress,
                                        gVcpu->Instruction.MemoryAccess, &glas[0].Size);
        if (!INT_SUCCESS(status))
        {
            char text[ND_MIN_BUF_SIZE];
            NdToText(&gVcpu->Instruction, 0, ND_MIN_BUF_SIZE, text);
            ERROR("[ERROR] IntDecDecodeAccessSize failed: 0x%08x for instruction '%s' "
                  "with access %d GLA = 0x%016llx, GPA = 0x%016llx\n",
                  status,
                  text,
                  AccessType,
                  LinearAddress,
                  PhysicalAddress);

            IntDumpInstruction(&gVcpu->Instruction, gVcpu->Regs.Rip);
            IntDumpArchRegs(&gVcpu->Regs);
            IntDumpGva(gVcpu->Regs.Rip & PAGE_MASK, PAGE_SIZE, gVcpu->Regs.Cr3);
            IntHookGpaDump();
            status = INT_STATUS_NOT_SUPPORTED;
            goto _exit_stop_count;
        }

        if (0 == glas[0].Size)
        {
            char text[ND_MIN_BUF_SIZE];
            NdToText(&gVcpu->Instruction, 0, ND_MIN_BUF_SIZE, text);
            WARNING("[WARNING] Access size 0 returned for instruction '%s' "
                    "with access %d GLA = 0x%016llx, GPA = 0x%016llx\n",
                    text,
                    AccessType,
                    LinearAddress,
                    PhysicalAddress);

            IntDumpInstruction(&gVcpu->Instruction, gVcpu->Regs.Rip);
            IntDumpArchRegs(&gVcpu->Regs);
            IntDumpGva(gVcpu->Regs.Rip & PAGE_MASK, PAGE_SIZE, gVcpu->Regs.Cr3);
            goto done_handling_instruction;
        }
    }
    else
    {
        // Multiple addresses accessed, decode each and every one of them.
        glacount = MAX_GLAS;

        status = IntDecGetAccessedMem(&gVcpu->Instruction,
                                      &gVcpu->Regs, NULL, glas, &glacount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecGetAccessedMem failed: 0x%x\n", status);
            status = INT_STATUS_NOT_SUPPORTED;
            goto _exit_stop_count;
        }
    }

    // Handle each accessed address.
    for (glaidx = 0; glaidx < glacount; glaidx++)
    {
        // This is REP instruction and the REP optimization is enabled. Handle up until the end of page.
        if (probe)
        {
            glas[glaidx].Size = (DWORD)MIN(glas[glaidx].Size * gVcpu->Regs.Rcx,
                                           PAGE_REMAINING(glas[glaidx].Gla));
        }

        tgla = glas[glaidx].Gla;
        tsize = glas[glaidx].Size;
        asize = 0;
        pgidx = pgcnt = 0;

        // Workaround for the RMW at page boundary emulation issue:
        // - The access must be write (specifically it must be RMW, but we handle any write)
        // - The access must be at a page boundary
        // - The second page must be read-only or COW
        // - We must be in user mode (there is no COW in kernel)

        if (IntHandlePageBoundaryCow(glas[glaidx].Gla, glas[glaidx].Size, glas[glaidx].Access, CpuNumber))
        {
            action = introGuestRetry;

            // we can skip processing the rest of the instruction, since we will retry it & we injected a #PF.
            goto done_handling_instruction;
        }

        // Translate each accessed page for this memory access.
        while (tsize != 0)
        {
            pages[pgidx].gla = tgla;
            pages[pgidx].size = tsize;

            if ((tgla & PAGE_MASK) == (LinearAddress & PAGE_MASK))
            {
                // We don't have to do the page walk if the linear address is the same page as the one passed to the
                // callback. We can use the provided PhysicalAddress page instead.
                pages[pgidx].gpa = (PhysicalAddress & PHYS_PAGE_MASK) + (tgla & PAGE_OFFSET);
            }
            else
            {
                status = IntTranslateVirtualAddress(tgla, gVcpu->Regs.Cr3, &pages[pgidx].gpa);
                if (!INT_SUCCESS(status))
                {
                    // We do not care about translation failures; if there would be a #PF generated for this access,
                    // it would not bother us, no matter what action we return:
                    // 1. allow -> emulation (and injection of #PF if needed) or single-step (#PF would be generated
                    //    naturally)
                    // 2. allowed virtual -> we handled the instruction entirely, integrator/HV does nothing
                    // 3. allowed patched -> emulation with context setting (and injection of #PF if needed)
                    // 4. not allowed -> we will skip the instruction, no matter what
                    // 5. ignored -> we shouldn't do anything anyway
                    // 6. retry -> the instruction will be retried normally; eventually, some different action will
                    //    be returned; this only happens if the current faulted page is not present or if the
                    //    page restrictions have been removed. Note that retry will be returned only when explicitly
                    //    removing protection from the current page after an execution attempt.
                    goto done_handling_instruction;
                }
            }

            asize = MIN(tsize, PAGE_REMAINING(tgla));
            tgla += asize;
            tsize -= asize;

            pgidx++, pgcnt++;
        }

        // If the instruction does a RMW access on the address, we need to call both the read and the write handlers.
        access = 0;

        if (glas[glaidx].Access & ND_ACCESS_ANY_READ)
        {
            access |= IG_EPT_HOOK_READ;
        }

        if (glas[glaidx].Access & ND_ACCESS_ANY_WRITE)
        {
            access |= IG_EPT_HOOK_WRITE;
        }

        // Handle the access.
        for (pgidx = 0; pgidx < pgcnt; pgidx++)
        {
            status = IntHandleMemAccess(pages[pgidx].gla, pages[pgidx].gpa, glas[glaidx].Size,
                                        &action, &cbkFound, &pageHooked, probe, access);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHandleMemAccess failed for 0x%016llx/0x%016llx with size 0x%x for type %d: %08x\n",
                      pages[pgidx].gpa, glas[glaidx].Gla, glas[glaidx].Size, access, status);
            }

            // We asked for probe only (for REPed instruction) and a callback was found. Disable the REP optimization
            // and retry the REPed instruction step by step.
            if (probe && cbkFound)
            {
                gVcpu->RepOptDisabled = TRUE;

                if (0 == gGuest.RepOptsDisableCount++)
                {
                    IntToggleRepOptimization(FALSE);

                    action = introGuestRetry;

                    goto done_handling_instruction;
                }
            }
        }
    }

done_handling_instruction:

    // Handle patched accesses.
    if (introGuestAllowedPatched == action)
    {
        PPATCH_BUFFER pb = &gVcpu->PatchBuffer;

        // The patch buffer is reset on each EPT violation callback invocation.
        if (pb->Valid)
        {
            pb->Valid = FALSE;

#ifndef USER_MODE
            // Try to emulate the read
            status = IntDecEmulateRead(&gVcpu->Instruction, pb->Data);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecEmulateRead failed: 0x%08x\n", status);
            }
            else
            {
                action = introGuestAllowedVirtual;
                goto _skip_emu_ctx;
            }
#endif // !USER_MODE

            status = IntSetIntroEmulatorContext(CpuNumber, pb->Gla, pb->Size, pb->Data);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSetIntroEmulatorContext failed: 0x%08x\n", status);
                IntDbgEnterDebugger();
                goto _exit_stop_count;
            }

#ifndef USER_MODE
_skip_emu_ctx:
            ;
#endif // !USER_MODE
        }
        else
        {
            ERROR("[ERROR] IntroGuestAllowedPatched is requested, but the patch buffer is not valid!\n");
            IntDbgEnterDebugger();
            status = INT_STATUS_INVALID_INTERNAL_STATE;
            goto _exit_stop_count;
        }
    }

    // Handle PT accesses. These will be emulated in-place.
    if (gVcpu->PtEmuBuffer.Emulated)
    {
        gVcpu->PtEmuBuffer.Emulated = FALSE;
        gVcpu->PtEmuBuffer.Valid = FALSE;

        // On PAE, PT writes are done in two steps, by two instructions (one for the low DWORD, one for the high DWORD)
        // In this case we will have two exits; avoid that by checking that the next instruction completes the PT
        // write started by the current one
        if (gVcpu->PtEmuBuffer.Partial && gVcpu->AccessSize == 4 && gGuest.PaeEnabled && !gGuest.Guest64)
        {
            QWORD nextGla = 0;

            // At this point we already emulated the first instruction so the RIP is pointing to the next one
            status = IntDecDecodeInstructionAtRipWithCache(gGuest.InstructionCache,
                                                           CpuNumber,
                                                           &gVcpu->Regs,
                                                           &gVcpu->Instruction,
                                                           gGuest.Mm.SystemCr3 != 0 ? 0 : DEC_OPT_NO_CACHE,
                                                           NULL,
                                                           NULL);
            if (!INT_SUCCESS(status))
            {
                goto _bail_out_of_next_emu;
            }

            if ((gVcpu->Instruction.Instruction != ND_INS_MOV) &&
                (gVcpu->Instruction.Instruction != ND_INS_XCHG) &&
                (gVcpu->Instruction.Instruction != ND_INS_CMPXCHG))
            {
                goto _bail_out_of_next_emu;
            }

            // Make sure that the second instruction is indeed one that modifies the
            // memory and that the access size is 4
            if ((gVcpu->Instruction.Operands[0].Type != ND_OP_MEM) ||
                (gVcpu->Instruction.Operands[0].Size != 4))
            {
                goto _bail_out_of_next_emu;
            }

            status = IntDecDecodeDestinationLinearAddressFromInstruction(&gVcpu->Instruction,
                                                                         &gVcpu->Regs, &nextGla);
            if (!INT_SUCCESS(status))
            {
                goto _bail_out_of_next_emu;
            }

            // There are two cases that interest us:
            //  MOV       dword ptr [edi], ecx
            //  MOV       dword ptr [edi + 4], ecx
            // Or:
            //  MOV       dword ptr [edi + 4], ecx
            //  MOV       dword ptr [edi], ecx
            // Check that we are in one of these, bail out if not
            if ((nextGla & ~7ull) != (LinearAddress & ~7ull))
            {
                goto _bail_out_of_next_emu;
            }

            // The gla was already computed by IntDecDecodeDestinationLinearAddressFromInstruction
            // Depending on the two cases from above, the pair of instructions already updated the low DWORD or the
            // high DWORD, update the PhysicalAddress to point to the right part of the PT entry
            LinearAddress = nextGla;
            PhysicalAddress = (PhysicalAddress & PHYS_PAGE_MASK) + (nextGla & PAGE_OFFSET);

            goto _process_again;
        }

_bail_out_of_next_emu:

        action = introGuestAllowedVirtual;
    }

_exit_pre_ret:
    // Special handling for introGuestRetry on EPT exec violations. We may request a retry when we cannot fetch the RIP,
    // for example. Sometimes, the instruction may be situated at a page boundary and be contained inside both pages.
    // In this case, if at least the first page is exec hooked and the second one is not present, we will induce an
    // infinite loop by requesting introGuestRetry, because the #PF on the second page will never be triggered since the
    // EPT violation on the first one will always take place first. In this case, we will manually inject the #PF on
    // the second page.
    if (action == introGuestRetry &&                                    // Retry requested.
        AccessType == IG_EPT_HOOK_EXECUTE &&                            // Execute fault.
        fetchfail &&                                                    // Instruction fetch failed due to page miss.
        (gVcpu->Regs.Rip & 0xFFF) + 15 > 0x1000)                        // There are chances the instruction spills.
    {
        // NOTE: This does not conflict with IntHandlePageBoundaryCow, as that one is triggered on write faults.
        IntHandleFetchRetryOnPageBoundary(CpuNumber);
    }

    // Handle introGuestAllowed on execution violations. These will end up being re-executed by Xen, so we must be
    // careful not to modify their access rights while they're re-executed.
    if (action == introGuestAllowed && AccessType == IG_EPT_HOOK_EXECUTE)
    {
        gVcpu->AllowOnExec = TRUE;
        gVcpu->AllowOnExecRip = gVcpu->Regs.Rip;
        gVcpu->AllowOnExecGpa = gVcpu->ExitGpa;
    }


    // Handle pre-return events. Don't inject #PF if we already injected one for the Xen workaround.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    status = INT_STATUS_SUCCESS;

    if (_InterlockedCompareExchange8(&gForceActionOnBeta, FALSE, TRUE))
    {
        status = INT_STATUS_FORCE_ACTION_ON_BETA;
    }

_exit_stop_count:
    STATS_EXIT(statsEptViolation);

    gVcpu->State = CPU_STATE_ACTIVE;

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] EPT callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    *Action = action;

    return status;
}


INTSTATUS
IntHandleMsrViolation(
    _In_ void *GuestHandle,
    _In_ DWORD Msr,
    _In_ IG_MSR_HOOK_TYPE Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ QWORD OriginalValue,
    _Inout_opt_ QWORD *NewValue,
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle a model specific register violation.
///
/// This callback is called on MSR violations. This handle will iterate the list of registered callbacks for that
/// particular MSR, and will call each one of them.
/// NOTE: Although read hooks can also be established on MSRs, Introcore does not make use of that, only write
/// hooks are set.
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  Msr             The accessed MSR.
/// @param[in]  Flags           MSR violation type (read or write).
/// @param[out] Action          Desired action.
/// @param[in]  OriginalValue   Original MSR value.
/// @param[out] NewValue        New MSR value. Can be modified, but whether the HV will take this into consideration
///                             or not is implementation dependent, so it is advisable to not modify this value.
/// @param[in]  CpuNumber       The VCPU number.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized yet.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If no callback is found for this MSR.
/// @retval #INT_STATUS_FATAL_ERROR A fatal error occurred, and the integrator should unload Introcore.
///
{
    INTSTATUS status;
    BOOLEAN found;
    BOOLEAN reinjectPerfAgent;

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    found = FALSE;

    *Action = introGuestAllowed;

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A MSR exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_7;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_MSR_VIOLATION;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    STATS_ENTER(statsMsrViolation);

    list_for_each(gGuest.MsrHooks->MsrHooksList, HOOK_MSR, pHook)
    {
        if (Msr == pHook->Msr)
        {
            found = TRUE;

            if (pHook->Disabled)
            {
                continue;
            }

            status = pHook->Callback(Msr, Flags, Action, pHook->Context, OriginalValue, NewValue);

            if (INT_STATUS_REMOVE_HOOK_ON_RET == status)
            {
                status = IntHookMsrRemoveHook(pHook);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookMsrRemoveHook failed: 0x%08x\n", status);
                }
            }
        }
    }

    // Only try to re-inject the PT Filter if the LSTAR was initialized
    reinjectPerfAgent = (IG_IA32_LSTAR == Msr) && (0 == OriginalValue) && (NULL != NewValue) && (0 != *NewValue);

    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM |
                                       POST_COMMIT_MSR |
                                       POST_INJECT_PF |
                                       (reinjectPerfAgent ? POST_RETRY_PERFAGENT : 0));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    if (found)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

    STATS_EXIT(statsMsrViolation);

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] MSR callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntHandleCrWrite(
    _In_ void *GuestHandle,
    _In_ DWORD Cr,
    _In_ DWORD CpuNumber,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle a control register violation.
///
/// This function is called by the integrator/HV on each CR violation. The handler will simply iterate the
/// list of registered callbacks for this particular CR, and call each one of them. Introcore only places
/// write hooks on the control registers; read hooks may trigger a very high performance impact.
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  Cr              The accessed CR.
/// @param[in]  CpuNumber       The VCPU number.
/// @param[in]  OldValue        Old CR value.
/// @param[in]  NewValue        New CR value.
/// @param[in]  Action          The desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized yet.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If no callback is found for this MSR.
/// @retval #INT_STATUS_FATAL_ERROR A fatal error occurred, and the integrator should unload Introcore.
///
{
    INTSTATUS status;
    BOOLEAN found;
    INTRO_ACTION action;

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    found = FALSE;
    action = introGuestAllowed;

    *Action = introGuestAllowed;

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A CR exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_3;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_CR_WRITE;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    STATS_ENTER(statsCrViolation);

    list_for_each(gGuest.CrHooks->CrHooksList, HOOK_CR, pHook)
    {
        if (Cr == pHook->Cr)
        {
            found = TRUE;

            if (pHook->Disabled)
            {
                continue;
            }

            status = pHook->Callback(pHook->Context, Cr, OldValue, NewValue, &action);

            if (INT_STATUS_REMOVE_HOOK_ON_RET == status)
            {
                status = IntHookCrRemoveHook(pHook);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookCrRemoveHook failed: 0x%08x\n", status);
                }
            }

            if (action > *Action)
            {
                *Action = action;
            }
        }
    }

    gVcpu->State = CPU_STATE_ACTIVE;

    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_COMMIT_CR | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    if (found)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

    STATS_EXIT(statsCrViolation);

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] CR%d callback set DisableOnReturn... We will try to disable introcore...\n", Cr);

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


static INTSTATUS
IntDispatchPtAsEpt(
    void
    )
///
/// @brief Dispatch a VMCALL issued by the PT filter as an EPT violation.
///
/// This function will act as the main EPT violation handler for very specific accesses filtered by the PT filter.
/// This function will be called when the PT filter intercepts a guest instruction which does a relevant modification
/// to a page-table entry. At that point, the PT filter will issue a VMCALL, but inside Introcore, in order to
/// maintain a good separation between events, we will directly invoke the main memory access handle in order
/// to treat the instruction as if it triggered an EPT violation. This function simply fills in the VCPU context
/// and calls the memory access function, which will treat the page-table write instruction. In addition, if the
/// page-table entry is not monitored by Introcore, it will be added to the PT cache, so as to not generate any
/// more VMCALLs for it, until it becomes hooked.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    BOOLEAN found, hooked;
    INTRO_ACTION action;

    STATS_ENTER(statsPtsFilterVmcall);

    action = introGuestAllowed;
    found = hooked = FALSE;

    gVcpu->PtContext = TRUE;

    gVcpu->PatchBuffer.Valid = FALSE;
    gVcpu->PtWriteCache.Valid = FALSE;

    gVcpu->PtEmuBuffer.Valid = TRUE;
    gVcpu->PtEmuBuffer.Emulated = TRUE;
    gVcpu->PtEmuBuffer.Old = gVcpu->Regs.R11;
    gVcpu->PtEmuBuffer.New = gVcpu->Regs.R10;
    gVcpu->Gpa = gVcpu->Regs.R9;
    gVcpu->Gla = gVcpu->Regs.R8;
    gVcpu->AccessSize = 8;

    // Handle EPT violations that came as #VE at our in-guest agent. We treat them as direct EPT violations inside the
    // mem access handler. Note that we don't handle multi-accesses here, since a #VE will only be triggered on single
    // known accesses - page tables, for now.
    status = IntHandleMemAccess(gVcpu->Gla, gVcpu->Gpa, 8, &action, &found, &hooked, FALSE, IG_EPT_HOOK_WRITE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHandleEptViolation failed: 0x%08x\n", status);
        STATS_EXIT(statsPtsFilterVmcall);
        return status;
    }

    if (!hooked)
    {
        status = IntPtiCacheAdd(gVcpu->Gpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPtsInt3CacheAdd failed for 0x%016llx: 0x%08x\n", gVcpu->Gpa, status);
        }
    }

    gVcpu->PtEmuBuffer.Emulated = FALSE;
    gVcpu->PtEmuBuffer.Valid = FALSE;
    gVcpu->PtWriteCache.Valid = FALSE;

    gVcpu->PtContext = FALSE;

    STATS_EXIT(statsPtsFilterVmcall);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDispatchVeAsEpt(
    void
    )
///
/// @brief Dispatch a VE as an EPT violation.
///
/// This function gets called when the VE agent issues a VMCALL, as a result from an in-guest VE which is considered
/// relevant. The VE agent will issue a VMCALL only for page-table writes which hit a protected page-table, and if
/// the write modifies a relevant bit. In that case, the agent will notify Introcore, which will handle the page-table
/// modification by properly updating the protection on the old/new pages. This function will fill in the VCPU
/// context (including the registers and the instruction, which are all provided in the VE info page) and will call
/// the memory access handler, which will behave as if the event was indeed generated as an EPT violation.
/// This function also has special handling for page-walks: due to KPTI, page-walks will always be emulated in the
/// context of the kernel CR3; however, sometimes, for some processes, the user CR3 PML4 entry will lack the A or
/// D bit, and since we cannot switch into the user-mode CR3 from inside the guest, we will simply ask Introcore
/// to handle those page walks, which are extremely rare, but would cause a guest hang otherwise (because the page-walk
/// VE would be triggered in an infinite loop, as the user CR3 would never end up having the A/D bits set).
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If a walk is requested from a Linux guest.
/// @retval #INT_STATUS_NOT_FOUND If the process with the current CR3 is not found.
///
{
    INTSTATUS status;
    BOOLEAN found, hooked, paused;
    QWORD eptvGpa, eptvGla;
    DWORD violType, mode;
    BYTE accessType;
    INTRO_ACTION action;

    action = introGuestAllowed;
    found = hooked = paused = FALSE;

    if (0 == (gVcpu->VeInfoPage->Qualification & (1ULL << 8)))
    {
        // This is a page-walk. The only reason the #VE agent asks for a page walk is to set the A bit inside the
        // user-mode CR3 of the current process. This happens because #VE agent makes the page-walk in the context
        // of the current CR3, but since it runs in kernel, the current CR3 will be the kernel CR3 (if KPTI is on).
        // Although normally all non-leaf entries are marked A/D, it seems that sometimes, an entry inside the user
        // CR3 PML4 is NOT accessed, causing an infinite loop due to the page-walker.
        PWIN_PROCESS_OBJECT pProc;
        PQWORD pPml4e;

        if (introGuestWindows != gGuest.OSType)
        {
            ERROR("[ERROR] #VE is supported only on Windows, how did we end up here?\n");
            return INT_STATUS_NOT_SUPPORTED;
        }

        TRACE("[#VE] Handling special user-mode page-walk, CR3 0x%016llx, GLA 0x%016llx\n",
              gVcpu->Regs.Cr3, gVcpu->VeInfoPage->GuestLinearAddress);

        pProc = IntWinProcFindObjectByCr3(gVcpu->Regs.Cr3);
        if (NULL == pProc)
        {
            ERROR("[ERROR] No process found for CR3 0x%016llx!\n", gVcpu->Regs.Cr3);
            return INT_STATUS_NOT_FOUND;
        }

        if ((pProc->UserCr3 != pProc->Cr3) && (pProc->UserCr3 >= 0x1000))
        {
            QWORD oldVal;

            status = IntGpaCacheFindAndAdd(gGuest.GpaCache, CLEAN_PHYS_ADDRESS64(pProc->UserCr3), &pPml4e);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGpaCacheFindAndAdd failed for GPA 0x%016llx: 0x%08x\n",
                      CLEAN_PHYS_ADDRESS64(pProc->UserCr3), status);
                return status;
            }

            pPml4e += PML4_INDEX(gVcpu->VeInfoPage->GuestLinearAddress);

            oldVal = *pPml4e;

            if (0 != (oldVal & PML4_P))
            {
                QWORD newVal;

                newVal = oldVal | PML4_A;

                _InterlockedCompareExchange64((INT64 *)pPml4e, (INT64)newVal, (INT64)oldVal);
            }

            IntGpaCacheRelease(gGuest.GpaCache, CLEAN_PHYS_ADDRESS64(pProc->UserCr3));
        }

        return INT_STATUS_SUCCESS;
    }

    // From here on, we're inside #VE context.
    gVcpu->VeContext = TRUE;

    // Fake the current EPTP index to be the default EPT view - we are normally in the protected view now, but the #VE
    // took place in the default view.
    gVcpu->EptpIndex = 0;

    // Fetch the GPA and GLA from the guest.
    eptvGpa = gVcpu->VeInfoPage->GuestPhysicalAddress;
    eptvGla = gVcpu->VeInfoPage->GuestLinearAddress;
    violType = (DWORD)gVcpu->VeInfoPage->Qualification;

    // Copy the #VE registers from the #VE info page; these are the real registers that were loaded when the violation
    // was triggered. Note that we do not save the old registers, because while we're inside #VE context, we inhibit
    // the modification of the real, global registers. Any SetGprs made from within the #VE context will only affect
    // the local cache (gVcpu->Regs) which will be used to propagate the new values in the #VE info page.
    gVcpu->Regs.Rax = gVcpu->VeInfoPage->Registers.RAX;
    gVcpu->Regs.Rcx = gVcpu->VeInfoPage->Registers.RCX;
    gVcpu->Regs.Rdx = gVcpu->VeInfoPage->Registers.RDX;
    gVcpu->Regs.Rbx = gVcpu->VeInfoPage->Registers.RBX;
    gVcpu->Regs.Rsp = gVcpu->VeInfoPage->Registers.RSP;
    gVcpu->Regs.Rbp = gVcpu->VeInfoPage->Registers.RBP;
    gVcpu->Regs.Rsi = gVcpu->VeInfoPage->Registers.RSI;
    gVcpu->Regs.Rdi = gVcpu->VeInfoPage->Registers.RDI;
    gVcpu->Regs.R8  = gVcpu->VeInfoPage->Registers.R8;
    gVcpu->Regs.R9  = gVcpu->VeInfoPage->Registers.R9;
    gVcpu->Regs.R10 = gVcpu->VeInfoPage->Registers.R10;
    gVcpu->Regs.R11 = gVcpu->VeInfoPage->Registers.R11;
    gVcpu->Regs.R12 = gVcpu->VeInfoPage->Registers.R12;
    gVcpu->Regs.R13 = gVcpu->VeInfoPage->Registers.R13;
    gVcpu->Regs.R14 = gVcpu->VeInfoPage->Registers.R14;
    gVcpu->Regs.R15 = gVcpu->VeInfoPage->Registers.R15;
    gVcpu->Regs.Rip = gVcpu->VeInfoPage->Registers.RIP;
    gVcpu->Regs.Flags = gVcpu->VeInfoPage->Registers.RFLAGS;

    violType &= 0x7;

    if (violType & 4)
    {
        accessType = IG_EPT_HOOK_EXECUTE;
    }
    else if (violType & 2)
    {
        accessType = IG_EPT_HOOK_READ | IG_EPT_HOOK_WRITE;
    }
    else
    {
        accessType = IG_EPT_HOOK_READ;
    }

    // Get the current operating mode. This should always be 64 bit, since we support #VE on 64 bit only.
    status = IntGetCurrentMode(gVcpu->Index, &mode);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Decode the already fetched instruction from the #VE info page.
    status = IntDecDecodeInstructionFromBuffer(gVcpu->VeInfoPage->Instruction, 16, mode, &gVcpu->Instruction);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (IntVeIsAgentRemapped(eptvGla))
    {
        IntPauseVcpus();
        paused = TRUE;
    }

    gVcpu->PtWriteCache.Valid = FALSE;

    gVcpu->PtEmuBuffer.Valid = TRUE;
    gVcpu->PtEmuBuffer.Emulated = TRUE;
    gVcpu->PtEmuBuffer.Old = gVcpu->VeInfoPage->OldValue;
    gVcpu->PtEmuBuffer.New = gVcpu->VeInfoPage->NewValue;

    status = IntGpaCachePatchAndAdd(gGuest.GpaCache, eptvGpa, 8, (PBYTE)&gVcpu->VeInfoPage->NewValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCachePatchAndAdd failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Handle EPT violations that came as #VE at our in-guest agent. We treat them as direct EPT violations inside the
    // mem access handler. Note that we don't handle multi-accesses here, since a #VE will only be triggered on single
    // known accesses - page tables, for now.
    status = IntHandleMemAccess(eptvGla, eptvGpa, 8, &action, &found, &hooked, FALSE, accessType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHandleEptViolation failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (paused)
    {
        IntResumeVcpus();
    }

    // Copy the (possibly) modified VE regs back to the #VE info page.
    gVcpu->VeInfoPage->Registers.RAX = gVcpu->Regs.Rax;
    gVcpu->VeInfoPage->Registers.RCX = gVcpu->Regs.Rcx;
    gVcpu->VeInfoPage->Registers.RDX = gVcpu->Regs.Rdx;
    gVcpu->VeInfoPage->Registers.RBX = gVcpu->Regs.Rbx;
    gVcpu->VeInfoPage->Registers.RSP = gVcpu->Regs.Rsp;
    gVcpu->VeInfoPage->Registers.RBP = gVcpu->Regs.Rbp;
    gVcpu->VeInfoPage->Registers.RSI = gVcpu->Regs.Rsi;
    gVcpu->VeInfoPage->Registers.RDI = gVcpu->Regs.Rdi;
    gVcpu->VeInfoPage->Registers.R8  = gVcpu->Regs.R8;
    gVcpu->VeInfoPage->Registers.R9  = gVcpu->Regs.R9;
    gVcpu->VeInfoPage->Registers.R10 = gVcpu->Regs.R10;
    gVcpu->VeInfoPage->Registers.R11 = gVcpu->Regs.R11;
    gVcpu->VeInfoPage->Registers.R12 = gVcpu->Regs.R12;
    gVcpu->VeInfoPage->Registers.R13 = gVcpu->Regs.R13;
    gVcpu->VeInfoPage->Registers.R14 = gVcpu->Regs.R14;
    gVcpu->VeInfoPage->Registers.R15 = gVcpu->Regs.R15;
    gVcpu->VeInfoPage->Registers.RIP = gVcpu->Regs.Rip;
    gVcpu->VeInfoPage->Registers.RFLAGS = gVcpu->Regs.Flags;

    // Done with the #VE context.
    gVcpu->PtEmuBuffer.Valid = FALSE;
    gVcpu->PtEmuBuffer.Emulated = FALSE;
    gVcpu->PtWriteCache.Valid = FALSE;

    gVcpu->VeContext = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHandleIntroCall(
    _In_ void *GuestHandle,
    _In_ QWORD Rip,
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle a VMCALL issued inside the guest.
///
/// This function will be called by the hypervisor whenever a VMCALL is executed inside the guest with a magic value
/// in EAX register. For the Xen hypervisor, this magic value involves several registers:
/// On x64: RAX = 0x22, RDI = 0x18, RSI = 0
/// On x86: EAX = 0x22, EBX = 0x18, ECX = 0
/// The EAX register will be overwritten by the HV on guest re-entry, so don't use it to pass the result of the VMCALL.
/// This function will dispatch the VMCALL to the following handlers, in this order:
/// 1. VE handler, if the RIP is inside the VE agent;
/// 2. PT handler, if the RIP is inside the PT filter;
/// 3. Detours, if VMCALL is used as the hyper call method;
/// 4. Agents.
/// After dispatching the VMCALL appropriately, this function will finally dispatch it as an EPT violation if either
/// the PT filter or the VE agent requested so.
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  Rip             RIP where the VMCALL originates.
/// @param[in]  CpuNumber       The VCPU number.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
/// @retval #INT_STATUS_NOT_FOUND If Introcore did not handle the VMCALL.
/// @retval #INT_STATUS_FATAL_ERROR If a fatal error occurred and the integrator should unload Introcore.
/// @retval #INT_STATUS_UNINIT_BUGCHECK If a bug-check occurred inside the guest and Introcore should be unloaded.
///
{
    INTSTATUS status;
    BOOLEAN bFound, bRaiseEptPt, bRaiseEptVe;

    bFound = bRaiseEptPt = bRaiseEptVe = FALSE;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A VMCALL exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_3;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_VMCALL;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    STATS_ENTER(statsVmcall);

    // Check the #VE agent.
    if (!bFound)
    {
        if (IntVeIsCurrentRipInAgent())
        {
            bFound = TRUE;

            status = IntVeHandleHypercall(CpuNumber);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVeHandleHypercall failed: 0x%08x\n", status);
            }

            if (INT_STATUS_RAISE_EPT == status)
            {
                bRaiseEptVe = TRUE;
            }
        }
    }

    // Check the PT cache agent.
    if (!bFound)
    {
        if (IntPtiIsPtrInAgent(gVcpu->Regs.Rip, ptrLiveRip))
        {
            if (gVcpu->Regs.R8 == 0)
            {
                // Request to remove the instruction, as it's faulty.
                IntPtiRemoveInstruction(gVcpu->Regs.R9);
            }
            else
            {
                // We assume only the raise-EPT VMCALL can be issued.
                bRaiseEptPt = TRUE;
            }

            bFound = TRUE;
        }
    }

    if (!bFound)
    {
        // Call the guest detours.
        status = IntDetCallCallback();
        if (!INT_SUCCESS(status))
        {
            if (INT_STATUS_NOT_FOUND != status)
            {
                ERROR("[ERROR] IntDetourCallCallback failed: 0x%08x\n", status);
            }
        }
        else
        {
            bFound = TRUE;
        }
    }

    if (!bFound)
    {
        // Call the generic agent handler
        status = IntAgentHandleVmcall(Rip);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentHandleVmcall failed: 0x%08x\n", status);
        }
        else
        {
            bFound = TRUE;
        }
    }

    if (bRaiseEptPt)
    {
        gVcpu->State = CPU_STATE_EPT_VIOLATION;

        status = IntDispatchPtAsEpt();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDispatchPtAsEpt failed: 0x%08x\n", status);
        }
    }
    else if (bRaiseEptVe)
    {
        gVcpu->State = CPU_STATE_EPT_VIOLATION;

        status = IntDispatchVeAsEpt();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDispatchVeAsEpt failed: 0x%08x\n", status);
        }
    }

    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    STATS_EXIT(statsVmcall);

    if (bFound)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] VMCALL callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

    if (INT_SUCCESS(status) && gGuest.BugCheckInProgress)
    {
        LOG("[INFO] VMCALL callback set BugCheckInProgress... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_UNINIT_BUGCHECK;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntHandleTimer(
    _In_ void *GuestHandle
    )
///
/// @brief Periodically called by the integrator, once every second.
///
/// This function is called every second. Tasks such as integrity checks can be done here.
/// The main tasks this handle carries are:
/// 1. Infinity hook protection;
/// 2. Integrity checks on structures that cannot be protected using EPT/SPP;
/// 3. Process token integrity checks - it will check every second if a system token has been stolen;
/// 4. System CR3 integrity - it will check every second to see of the System CR3 has been modified;
/// 5. Self-map integrity - it will check every second of the self-map entry inside the page-tables has been modified;
/// 6. Re-inject page-faults that did not get to be processes in the last second;
/// 7. Do PT integrity checks; since the PT monitors page-tables by intercepting instructions inside NT that modify
/// them, there is a chance that someone else could modify a page-table entry without us knowing; this integrity
/// check will make sure that every page-table entry that we monitor hasn't been tampered with;
/// 8. Once every hour, dump performance statistics;
/// NOTE: this may be called on any processor. However, code must not make assumptions regarding  the PCPUS/VCPUS
/// it gets called on, and neither should it assume that it will be called on more than one processor.
/// This function will get called every second. This also ensures us that every second, the hooks will be
/// committed or cleaned up.
/// IMPORTANT: Any function called here must be #TIMER_FRIENDLY: it must not rely on VCPU state or on the fact
/// that a "current VCPU exits" - it should assume that all the VCPUs are running and it must rely only on the global,
/// known state of the guest: system CR3, cached paging mode, etc. Doing any kind of state query will lead to a VCPU
/// pause, will return the state of that VCPU, but the VCPU will then be resumed, resulting in a dangling state,
/// which may quickly become invalid. If guest state is required, make sure you pause all the VCPUs.
///
/// @param[in]  GuestHandle     The guest handle.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
///
{
    INTSTATUS status;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    gEventId++;

#if defined(CFG_PAUSE_VCPUS_ON_EVENTS)
    IntPauseVcpus(); // Must pause on Xen, as the VCPUs run when the timer events comes.
#endif

    if (!gGuest.Initialized)
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto release_and_exit;
    }

    gVcpu = &gGuest.VcpuArray[0];

    if (gGuest.ShutDown)
    {
        status = INT_STATUS_SUCCESS;
        goto release_and_exit;
    }

    gGuest.TimerCalls++;

    STATS_ENTER(statsTimer);

    if (0 == gGuest.TimerCalls % IG_TIMER_FREQUENCY)
    {
        /// It would be nice to pause the guest while we do the checks; However,
        /// since we're doing read-only operations and the protected areas should
        /// not be modified during the normal usage, we can safely let all other
        /// processors run code.

        // Don't check anything until the exceptions are not loaded, we may end up excepting unwanted writes
        if (IntUpdateAreExceptionsLoaded())
        {
            // Once every timer tick, on static init, try to initialize Infinity Hook protection
            if (gGuest.OSType == introGuestWindows)
            {
                status = IntWinInfHookProtect();
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinInfHookProtect failed: 0x%08x\n", status);
                }
            }

            // Once every timer tick, do the integrity checks.
            status = IntIntegrityCheckAll();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIntegrityCheckAll failed: 0x%08x\n", status);
            }

            // Once every timer tick, make sure no process tokens have been stolen by another processes,
            // and no token privileges have been modified in a malicious way, indicating a LPE.
            status = IntWinTokenCheckIntegrity();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinTokenCheckIntegrity failed: 0x%x\n", status);
            }

            // Once every timer tick, make sure no process security descriptor pointers or ACLs (SACL/DACL) have
            // been modified.
            status = IntWinSDCheckIntegrity();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSDCheckIntegrity failed: 0x%x\n", status);
            }

            // Once every timer tick, make sure that the System CR3 remained the same.
            status = IntWinProcValidateSystemCr3();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcValidateSystemCr3 failed: 0x%08x\n", status);
            }

            // Once every timer tick, validate self map entries
            status = IntWinSelfMapValidateSelfMapEntries();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcValidateSelfMapEntries failed: 0x%08x\n", status);
            }

            // Once every timer tick, verify SharedUserData integrity.
            status = IntWinSudCheckIntegrity();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSudCheckIntegrity failed: 0x%08x\n", status);
            }

        }

        // Re-schedule timed-out page-faults.
        IntSwapMemReinjectFailedPF();
    }

#ifdef DEBUG
    // Dump the #VE statistics every one minute on debug.
    if (0 == gGuest.TimerCalls % (IG_TIMER_FREQUENCY * 60))
    {
        IntVeDumpStats();
    }
#endif

    // Check PTS integrity once every 5 seconds
#ifdef USER_MODE
    if (0 == gGuest.TimerCalls % (IG_TIMER_FREQUENCY * 5))
    {
        status = IntHookPtsCheckIntegrity();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsCheckIntegrity failed: 0x%08x\n", status);
        }

    }
#endif // USER_MODE

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    // Unless we made an explicit goto release_and_exit, we assume we don't want to propagate an error.
    status = INT_STATUS_SUCCESS;

    STATS_EXIT(statsTimer);

    if (0 == gGuest.TimerCalls % (IG_TIMER_FREQUENCY * 3600))
    {
        // Dump performance stats every 60 minutes.
        IntStatsDumpAll();
        IntVeDumpStats();

        // Reset the number of NT EAT reads every 60 minutes.
        if (introGuestWindows == gGuest.OSType && gGuest.KernelDriver)
        {
            gGuest.KernelDriver->Win.EatReadCount = 0;
        }
    }

    if (gInjectVeLoader)
    {
        IntGuestUpdateCoreOptions(gGuest.CoreOptions.Current | INTRO_OPT_VE);
        gInjectVeLoader = FALSE;
    }
    if (gInjectVeUnloader)
    {
        IntGuestUpdateCoreOptions(gGuest.CoreOptions.Current & ~INTRO_OPT_VE);
        gInjectVeUnloader = FALSE;
    }

    if (gLoadPtDriver)
    {
        IntGuestUpdateCoreOptions(gGuest.CoreOptions.Current | INTRO_OPT_IN_GUEST_PT_FILTER);
        gLoadPtDriver = FALSE;
    }
    if (gUnloadPtDriver)
    {
        IntGuestUpdateCoreOptions(gGuest.CoreOptions.Current & ~INTRO_OPT_IN_GUEST_PT_FILTER);
        gUnloadPtDriver = FALSE;
    }


release_and_exit:

#if defined(CFG_PAUSE_VCPUS_ON_EVENTS)
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntHandleXcrWrite(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle extended control registers writes.
///
/// This function handles the XSETBV instruction, which modifies XCRs. Currently, only XCR0 can be intercepted.
/// Even this is intercepted in order to aid into activating protection, and it is not protected against attacks.
/// This function will iterate the list of XCR callbacks, and it will call each one.
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  CpuNumber       The VCPU number.
/// @param[out] Action          The desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
/// @retval #INT_STATUS_NOT_FOUND If Introcore did not handle the VMCALL.
/// @retval #INT_STATUS_FATAL_ERROR If a fatal error occurred and the integrator should unload Introcore.
///
{
    INTSTATUS status;
    BOOLEAN found;
    QWORD newValue;
    DWORD xcr;
    INTRO_ACTION action;

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    found = FALSE;
    *Action = introGuestAllowed;
    action = introGuestAllowed;

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A XCR exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_3;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_XCR_WRITE;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    xcr = (DWORD)gVcpu->Regs.Rcx;

    newValue = ((QWORD)(gVcpu->Regs.Rdx & 0xFFFFFFFF) << 32) |
               (gVcpu->Regs.Rax & 0xFFFFFFFF);

    STATS_ENTER(statsXcrViolation);

    gVcpu->Xcr0 = newValue;

    list_for_each(gGuest.XcrHooks->XcrHooksList, HOOK_XCR, pHook)
    {
        if (xcr == pHook->Xcr)
        {
            found = TRUE;

            if (pHook->Disabled)
            {
                continue;
            }

            status = pHook->Callback(pHook->Context, xcr, &action);

            if (INT_STATUS_REMOVE_HOOK_ON_RET == status)
            {
                status = IntHookXcrRemoveHook(pHook);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookXcrRemoveHook failed: 0x%08x\n", status);
                }
            }

            if (action > *Action)
            {
                *Action = action;
            }
        }
    }

    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_COMMIT_XCR | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    if (found)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

    STATS_EXIT(statsXcrViolation);

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] XCR callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntHandleBreakpoint(
    _In_ void *GuestHandle,
    _In_ QWORD GuestPhysicalAddress,
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle guest breakpoints.
///
/// This handler is called by the integrator whenever a breakpoint (INT3) takes place inside the guest. This function
/// will just dispatch the event to an appropriate Introcore handler, in this order:
/// 1. Detours;
/// 2. Agents;
/// 3. The PT filter.
/// If no handler claims ownership for a particular INT3, we will disassemble the instruction pointed by the current
/// RIP. If indeed there is an INT3 there, we will re-inject it to the guest, as it probably really is an in-guest
/// breakpoint. If the instruction is not INT3, it may have been replaced by the PT filter, for example, when
/// inspecting a candidate instruction. In that case, we will simply re-entry inside the guest at the same RIP.
/// Handling the breakpoint can be done in three ways:
/// 1. Reinject it; if the INT3 wasn't triggered by our detours, agents or PT filter, it gets reinjected;
/// 2. Skip it; if the INT3 was handled by us, simply move the RIP over it;
/// 3. Re-entry at the same instruction; if introcore replaced the INT3 with something else in the meantime,
/// simply re-enter at the same RIP.
///
/// @param[in]  GuestHandle             The guest handle.
/// @param[in]  GuestPhysicalAddress    Unused.
/// @param[in]  CpuNumber               The VCPU number.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
/// @retval #INT_STATUS_NOT_FOUND If Introcore did not handle the VMCALL.
/// @retval #INT_STATUS_FATAL_ERROR If a fatal error occurred and the integrator should unload Introcore.
/// @retval #INT_STATUS_UNINIT_BUGCHECK If a bug-check occurred inside the guest and Introcore should be unloaded.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS regs;
    BOOLEAN found, emulated, noemu;

    UNREFERENCED_PARAMETER(GuestPhysicalAddress);

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    found = emulated = noemu = FALSE;

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(!gGuest.GuestInitialized))
    {
        WARNING("[WARNING] A BP exit came for cpu %d while the guest was not initialized. Will ignore.\n", CpuNumber);
        // Here we have to return an error to signal the fact that this #BP was not set by introcore
        status = INT_STATUS_NOT_INITIALIZED;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A BP exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_3;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_BREAKPOINT;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    regs = &gVcpu->Regs;

    STATS_ENTER(statsInt3);

    // Handle guest detours.
    if (!found)
    {
        status = IntDetCallCallback();
        if (INT_SUCCESS(status))
        {
            found = TRUE;

            if (INT_STATUS_NO_DETOUR_EMU == status)
            {
                noemu = TRUE;
            }
        }
        else
        {
            if (INT_STATUS_NOT_FOUND != status)
            {
                ERROR("[ERROR] IntDetCallCallback failed: 0x%08x\n", status);
            }
        }
    }

    // If no INT3 handler found, call the generic agents handler.
    if (!found)
    {
        status = IntAgentHandleInt3(regs->Rip, CpuNumber);
        if (INT_SUCCESS(status))
        {
            // An agent handled this, we're good.
            found = TRUE;


            if (INT_STATUS_NO_DETOUR_EMU == status)
            {
                noemu = TRUE;
            }
        }
        else
        {
            if (INT_STATUS_NOT_FOUND != status)
            {
                ERROR("[ERROR] IntAgentHandleInt3 failed: 0x%08x\n", status);
            }
        }
    }

    // If no detour or agent handler found, check the PT write candidates.
    if (!found)
    {
        status = IntPtiHandleInt3();
        if (INT_SUCCESS(status))
        {
            // An agent handled this, we're good.
            found = TRUE;


            if (INT_STATUS_NO_DETOUR_EMU == status)
            {
                noemu = TRUE;
            }
        }
        else
        {
            if (INT_STATUS_NOT_FOUND != status)
            {
                ERROR("[ERROR] IntAgentHandleInt3 failed: 0x%08x\n", status);
            }
        }
    }

    if (!found)
    {
        // So we don't have agents, detours or pt filter; however, this may happen after we remove candidate
        // PT instructions, since an INT3 may remain pending while we remove all the breakpoints from memory.
        // We can easily handle this may reading the byte at RIP and checking if it is indeed an INT3. If it is,
        // we will reinject it, otherwise, we'll ignore it.
        // Note that we have to really decode the instruction, because someone may use encodings such CD03 or 48CC.
        INSTRUX instrux;

        status = IntDecDecodeInstructionAtRip(CpuNumber, regs, NULL, &instrux);
        if (INT_SUCCESS(status))
        {
            if (instrux.Instruction == ND_INS_INT3 || (instrux.Instruction == ND_INS_INT && instrux.Immediate1 == 3))
            {
                // This is a legit int3.
                TRACE("[INFO] We have a breakpoint exit with instruction %s at RIP %llx, will reinject\n",
                      instrux.Mnemonic, regs->Rip);
            }
            else
            {
                // Not really INT3 there in memory, we can ignore it.
                TRACE("[INFO] We have a breakpoint exit with instruction %s at RIP %llx, will ignore\n",
                      instrux.Mnemonic, regs->Rip);
                found = noemu = TRUE;
            }
        }
    }

    // Skip the INT3 instruction if we haven't already emulated it and we do require emulation.
    if (found && !emulated && !noemu)
    {
        regs->Rip++;

        status = IntSetGprs(CpuNumber, regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        }
    }

    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    if (found)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

    STATS_EXIT(statsInt3);

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] BP callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

    if (INT_SUCCESS(status) && gGuest.BugCheckInProgress)
    {
        ERROR("[ERROR] BP callback set BugCheckInProgress... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_UNINIT_BUGCHECK;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


static INTSTATUS
IntHandleEventInjection(
    _In_ void *GuestHandle,
    _In_ DWORD Vector,
    _In_ QWORD ErrorCode,
    _In_ QWORD Cr2,
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle event injections inside the guest.
///
/// This event will be the first event to be generated once we inject an exception on CPU CpuNumber. This is used
/// to know if an exception that we injected inside the guest really got injected. If something else got injected,
/// Introcore can retry the injection at a later point. This simplifies the exception injection algorithm, especially
/// because the HV may inject other things inside the guest.
/// This function will check if the HV injected our PF or UD (which we requested earlier).
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  Vector          The vector that got injected inside the guest.
/// @param[in]  ErrorCode       The delivered error code, if any.
/// @param[in]  Cr2             The CR2, if a PF was injected.
/// @param[in]  CpuNumber       The VCPU number.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is used.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(ErrorCode);

    if (GuestHandle == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus();
#endif

    if (__unlikely(!gGuest.Initialized))
    {
        // We need to exit with success, since most likely the introspection was disabled in the meantime.
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A VMCALL exit came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_5;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    gVcpu->State = CPU_STATE_EVENT_INJECTION;

    status = IntGetGprs(CpuNumber, &gVcpu->Regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto _exit_release;
    }

    TRACE("[INFO] Injected vector 0x%02x, CR2 0x%016llx, ErrorCode %llx, CPU %d\n", Vector, Cr2, ErrorCode, CpuNumber);

    STATS_ENTER(statsEventInjection);

    // We don't expect this callback to be called with an invalid exception state.
    if (!gVcpu->Exception.Valid)
    {
        WARNING("[WARNING] IntHandleEventInjection was called, but no injection was done!\n");
    }

    if (((gVcpu->Exception.Vector != Vector) && (gVcpu->Exception.Vector == VECTOR_PF)) ||
        (gVcpu->Exception.Cr2 & PAGE_MASK) != (Cr2 & PAGE_MASK))
    {
        // Something was injected, but it either wasn't a #PF, or the CR2 did not match.
        IntSwapMemCancelPendingPF(gVcpu->Exception.Cr2);
    }

    if (gVcpu->Exception.Vector == Vector && Vector == VECTOR_UD)
    {
        if (NULL == gVcpu->CurrentUD)
        {
            ERROR("[ERROR] UD INFO is NULL\n");
        }
        else
        {
            IntUDRemoveEntry(&gVcpu->CurrentUD);
        }
    }


    // Something got injected, reset this exception.
    gVcpu->Exception.Valid = FALSE;

    // We always set this to NULL, as it is set with the proper value on every #UD request
    gVcpu->CurrentUD = NULL;

    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

    status = INT_STATUS_SUCCESS;

    STATS_EXIT(statsEventInjection);

_exit_release:

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntHandleDtrViolation(
    _In_ void *GuestHandle,
    _In_ DWORD Flags,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle GDTR, IDTR, LDTR, TR accesses.
///
/// This function is called on descriptor table registers accesses. This function will iterate registered callbacks
/// and it will call all of them. Special handling is done, however, for these instructions, as they generate a
/// descriptor table access VM exit before doing any kind of memory checks; therefore, emulating such an instruction
/// may lead to an EPT protection bypass (since the HV may not check EPT access rights when emulating instructions).
/// As a result, we do some serious checks when handling these instructions:
/// 1. Bail out if the instruction is not LIDT, LGDT, LLDT, LTR, SIDT, SGDT, SLDT, STR;
/// 2. Bail out if the instruction doesn't operate on memory - we are only interested in LGDT/LIDT, which can only
/// operate on memory operands;
/// 3. Decode the accessed linear address, and call the CoW and regular memory access handlers for that address;
/// 4. If the access is valid, carry on by calling the LIDT/LGDT handlers.
/// NOTE: The instruction will be allowed by default when loading a non-null value over a previously null value;
/// this is basically the initialization of that register.
///
/// @param[in]  GuestHandle     The guest handle.
/// @param[in]  Flags           Descriptor table accessed & accessed type. Check out #IG_DESC_ACCESS.
/// @param[in]  CpuNumber       The VCPU number.
/// @param[out] Action          Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
/// @retval #INT_STATUS_FATAL_ERROR If a fatal error occurred and Introcore should be unloaded.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS regs;
    PINSTRUX instruction;
    QWORD gla, gpa, gla2, base;
    DTR newDtr = {0}, oldDtr = {0};
    BOOLEAN cacheuse, cbkfound, pagefound;
    WORD limit;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *Action = introGuestAllowed;
    gla = base = 0;
    limit = 0;
    cbkfound = pagefound = FALSE;

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus(GuestHandle);
#endif

    if (__unlikely(!gGuest.GuestInitialized))
    {
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto _exit_release;
    }

    if (__unlikely(CpuNumber >= gGuest.CpuCount))
    {
        ERROR("[ERROR] A dtr violation came for cpu %d, but we have only %d\n", CpuNumber, gGuest.CpuCount);
        status = INT_STATUS_INVALID_PARAMETER_3;
        goto _exit_release;
    }

    gVcpu = &gGuest.VcpuArray[CpuNumber];
    regs = &gVcpu->Regs;
    instruction = &gVcpu->Instruction;
    gVcpu->State = CPU_STATE_DTR_LOAD;

    status = IntGetGprs(CpuNumber, regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    cacheuse = (gGuest.Mm.SystemCr3 != 0);
    status = IntDecDecodeInstructionAtRipWithCache(gGuest.InstructionCache,
                                                   CpuNumber,
                                                   regs,
                                                   instruction,
                                                   cacheuse ? 0 : DEC_OPT_NO_CACHE,
                                                   NULL,
                                                   NULL);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        TRACE("[INFO] The page containing the RIP has been swapped out; will retry the instruction.\n");
        *Action = introGuestRetry;
        status = INT_STATUS_SUCCESS;
        goto done_handling_dtr_violation;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeInstructionAtRipWithCache failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    // Exits triggered by other instructions are fishy - only LIDT, LGDT, SIDT, SGDT can trigger such exits.
    // If, however, we get other instructions, we will retry them, as they were probably been mangled inside the guest.
    if (instruction->Instruction != ND_INS_LIDT && instruction->Instruction != ND_INS_SIDT &&
        instruction->Instruction != ND_INS_LGDT && instruction->Instruction != ND_INS_SGDT &&
        instruction->Instruction != ND_INS_LLDT && instruction->Instruction != ND_INS_SLDT &&
        instruction->Instruction != ND_INS_LTR && instruction->Instruction != ND_INS_STR)
    {
        ERROR("[ERROR] We have a DTR exit, but the instruction is not appropriate: %s\n", instruction->Mnemonic);
        *Action = introGuestRetry;
        goto done_handling_dtr_violation;
    }

    // Not operating on memory, we can bail out. Note that LIDT, LGDT, SIDT, SGDT (the instructions that interest us)
    // can only operate on memory, so this condition basically covers register access for LLDT, LTR, SLDT, STR.
    if (instruction->Operands[0].Type != ND_OP_MEM)
    {
        goto done_handling_dtr_violation;
    }

    // Get the new value from the instruction by getting the address which stores the value and then reading it. We also
    // need it in order to handle the memory access caused by this instruction.
    status = IntDecComputeLinearAddress(instruction, &instruction->Operands[0], regs, &gla);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecComputeLinearAddress failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    if (IntHandleCowOnPage(gla & PAGE_MASK, CpuNumber, instruction->Operands[0].Access.Access))
    {
        *Action = introGuestRetry;

        // we can skip processing the rest of the violation, since we will retry it & we injected a #PF.
        goto done_handling_dtr_violation;
    }

    if (IntHandlePageBoundaryCow(gla, instruction->Operands[0].Size, instruction->Operands[0].Access.Access, CpuNumber))
    {
        *Action = introGuestRetry;

        // we can skip processing the rest of the violation, since we will retry it & we injected a #PF.
        goto done_handling_dtr_violation;
    }

    status = IntTranslateVirtualAddress(gla, regs->Cr3, &gpa);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddress failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    status = IntHandleMemAccess(gla, gpa, instruction->Operands[0].Size, Action, &cbkfound, &pagefound, FALSE,
                                (instruction->Operands[0].Access.Write ? IG_EPT_HOOK_WRITE : IG_EPT_HOOK_READ));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHandleMemAccess failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    if (((gla + instruction->Operands[0].Size) & PAGE_MASK) != (gla & PAGE_MASK))
    {
        // Page boundary access.
        gla2 = (gla + instruction->Operands[0].Size) & PAGE_MASK;

        status = IntTranslateVirtualAddress(gla2, regs->Cr3, &gpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddress failed: 0x%08x\n", status);
            goto done_handling_dtr_violation;
        }

        status = IntHandleMemAccess(gla2, gpa, instruction->Operands[0].Size, Action, &cbkfound, &pagefound, FALSE,
                                    (instruction->Operands[0].Access.Write ? IG_EPT_HOOK_WRITE : IG_EPT_HOOK_READ));
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHandleMemAccess failed: 0x%08x\n", status);
            goto done_handling_dtr_violation;
        }
    }

    // If the memory handler returns anything other than allowed, we will obey that status;
    if (*Action != introGuestAllowed)
    {
        LOG("[INFO] The memory handling callback returned action %d for instruction %s!\n",
            *Action,
            instruction->Mnemonic);

        goto done_handling_dtr_violation;
    }

    // We can bail out on SIDT, SGDT, STR, SLDT, LTR, LLDT - they do not interest us.
    if (ND_INS_LIDT != instruction->Instruction && ND_INS_LGDT != instruction->Instruction)
    {
        //TRACE("[INFO] SIDT/SGDT    (instruction code: %04d) came. Will allow.\n", instruction->Instruction);
        goto done_handling_dtr_violation;
    }

    // Get the original value from DTR (also, here we do the specific DTR stuff)
    if (ND_INS_LIDT == instruction->Instruction)
    {
        status = IntIdtFindBase(CpuNumber, &base, &limit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIdtFindBase failed: 0x%08x\n", status);
            goto done_handling_dtr_violation;
        }
    }
    else if (ND_INS_LGDT == instruction->Instruction)
    {
        status = IntGdtFindBase(CpuNumber, &base, &limit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGdtFindBase failed: 0x%08x\n", status);
            goto done_handling_dtr_violation;
        }
    }
    else
    {
        WARNING("[WARNING] Unknown instruction on DTR violation callback. Instruction code: %04d. Rip: 0x%016llx\n",
                instruction->Instruction, regs->Rip);
        goto done_handling_dtr_violation;
    }

    oldDtr.Base = base;
    oldDtr.Limit = limit;

    status = IntVirtMemRead(gla, gGuest.WordSize + sizeof(WORD), regs->Cr3, &newDtr, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto done_handling_dtr_violation;
    }

    // If the old value is the same as the new one, then we will allow it.
    // If the base of the old value is 0 and the base of the new value is different than 0, then we will allow it.
    if ((0 == oldDtr.Base && 0 != newDtr.Base) ||
        (oldDtr.Base == newDtr.Base && oldDtr.Limit == newDtr.Limit))
    {
        goto done_handling_dtr_violation;
    }

    STATS_ENTER(statsDtrViolation);

    list_for_each(gGuest.DtrHooks->DtrHooksList, HOOK_DTR, pHook)
    {
        if (pHook->Disabled)
        {
            continue;
        }

        // We compare the flags for which the hook was set vs. the flags reported to us. They have to be identical
        /// (for example, GDTR READ, IDTR WRITE, etc.).
        if (pHook->Flags == Flags)
        {
            status = pHook->Callback(&oldDtr, &newDtr, Flags, Action);

            if (INT_STATUS_REMOVE_HOOK_ON_RET == status)
            {
                status = IntHookDtrRemoveHook(pHook);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookIdtrRemoveHook failed: 0x%08x\n", status);
                }
            }
        }
    }

    STATS_EXIT(statsDtrViolation);

done_handling_dtr_violation:
    gVcpu->State = CPU_STATE_ACTIVE;

    // Handle pre-return events.
    status = IntGuestPreReturnCallback(POST_COMMIT_MEM | POST_COMMIT_DTR | POST_INJECT_PF);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestPreReturnCallback failed: 0x%08x\n", status);
    }

_exit_release:
    if (_InterlockedCompareExchange8(&gGuest.DisableOnReturn, FALSE, TRUE))
    {
        ERROR("[ERROR] DTR callback set DisableOnReturn... We will try to disable introcore...\n");

        IntGuestDisableIntro(0);

        status = INT_STATUS_FATAL_ERROR;
    }

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntEnginesResultCallback(
    _In_ void *GuestHandle,
    _In_ PENG_NOTIFICATION_HEADER EngineNotification
    )
///
/// @brief Handler called by the integrator as soon as the engines report a scan result for a buffer.
///
/// Introcore may request the AV engines to scan certain memory buffers (for example, Powershell command lines or
/// memory areas that get executed inside the guest). Since the scanning is done in a different thread/process,
/// and due to performance concerns, we resume guest execution as soon as we have sent the buffer to be scanned.
/// When the engines finish the scan, Introcore will be notified of the result via this handler. This handler
/// simply dispatches the result to the appropriate callback, and they will send an alert, if a detection
/// was generated. Currently, only two types of buffers are scanned using the AV engines:
/// 1. Executed memory pages which are deemed legit by Introcore
/// 2. Powershell command lines
/// If other types of buffers need to be scanned, make sure you add the result handling here as well.
///
/// @param[in]  GuestHandle         The guest handle.
/// @param[in]  EngineNotification  A structure describing the buffer that was scanned and the scan result.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == GuestHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == EngineNotification)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntSpinLockAcquire(gLock);

    gEventId++;

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntPauseVcpus(GuestHandle);
#endif

    if (__unlikely(!gGuest.GuestInitialized))
    {
        status = INT_STATUS_NOT_INITIALIZED_HINT;
        goto done_handling_engine_result;
    }


    if (introEngineNotificationCodeExecution == EngineNotification->Type)
    {
        PENG_NOTIFICATION_CODE_EXEC codeExecEngineNotification = (PENG_NOTIFICATION_CODE_EXEC)EngineNotification;

        status = IntHandleExecCallback(codeExecEngineNotification);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHandleExecCallback failed: 0x%08x\n", status);
        }
    }
    else if (introEngineNotificationCmdLine == EngineNotification->Type)
    {
        PENG_NOTIFICATION_CMD_LINE cmdLineEngineNotification = (PENG_NOTIFICATION_CMD_LINE)EngineNotification;

        if (gGuest.OSType == introGuestWindows)
        {
            status = IntWinHandleCmdLineCallback(cmdLineEngineNotification);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinHandleCmdLineCallback failed: 0x%08x\n", status);
            }
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            status = IntLixHandleCmdLineCallback(cmdLineEngineNotification);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixCmdLineHandleCallback failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        ERROR("[ERROR] Unknown engine notification type, value:%x\n", EngineNotification->Type);
    }

done_handling_engine_result:

#ifdef CFG_PAUSE_VCPUS_ON_EVENTS
    IntResumeVcpus();
#endif

    IntSpinLockRelease(gLock);

    return status;
}


INTSTATUS
IntCallbacksInit(
    void
    )
///
/// @brief Initialize the callbacks.
///
/// Most of the callbacks are initialized here. As soon as a callback is registered for a certain type of event,
/// Introcore can start processing them.
/// NOTE: Some callbacks, such as the breakpoint handler or the EPT violation handler are registered on the
/// init flow, so as to avoid having to handle many irrelevant events while we initialize.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntRegisterVmxTimerHandler(IntHandleTimer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterVmxTimerHandler failed: 0x%08x\n", status);
        return status;
    }

    status = IntRegisterIntroCallHandler(IntHandleIntroCall);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterIntroCallHandler failed: 0x%08x\n", status);
        return status;
    }

    status = IntRegisterEventInjectionHandler(IntHandleEventInjection);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterEventInjectionHandler failed: 0x%08x\n", status);
        return status;
    }

    status = IntRegisterEnginesResultCallback(IntEnginesResultCallback);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterEnginesResultCallback failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCallbacksUnInit(
    void
    )
///
/// @brief Uninit all the Introcore callbacks.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    IntUnregisterVmxTimerHandler();

    IntUnregisterIntroCallHandler();

    // NOTE: This is activated differently for Linux & Windows, but no harm if it's unregistered here.
    IntUnregisterBreakpointHandler();

    IntUnregisterEventInjectionHandler();

    IntUnregisterEnginesResultCalback();

    return INT_STATUS_SUCCESS;
}
