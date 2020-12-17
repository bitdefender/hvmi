/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winsud.h"
#include "hook.h"
#include "exceptions.h"
#include "alerts.h"
#include "winthread.h"
#include "winprocesshp.h"
#include "crc32.h"
#include "utils.h"


///
/// @file winsud.c
/// @brief  Handles violations involving the SharedUserData structure.
///
/// The SharedUserData structure (nt!KUSER_SHARED_DATA) contains various system specific data that is shared
/// between the kernel and all the processes running on the system. In kernel mode it is hardcoded to
/// 0xFFFFF78000000000 on x64, or 0xFFDF0000 on x86, while in user mode it is always mapped to 0x7FFE0000.
/// The shared page is writable only from kernel mode and is not executable, but by changing the rights
/// from the page table hierarchy, one can execute from inside this page. Since the page is hardcoded,
/// one can leverage an arbitrary write vulnerability in order to place a shellcode after the SharedUserData
/// structure, leading to a Remote Code Execution. Moreover, since the page is mapped in all processes,
/// it can be used to deliver various payloads through it. For this purpose we will execute-protect the
/// SharedUserData page through EPT.
///
/// The SharedUserData page may be used to store some fake structures in some complex exploitation scenarios,
/// for example MDLs in SMBGhost. For this purpose, we verify once every second that after the SharedUserData
/// structure, the rest of the page is filled with 0. Moreover, some fixed fields which may be messed with
/// for exploitation purposes are also checked in order to detect modifications.
///


/// @brief  The hook object protecting against executions on SharedUserData.
static HOOK_GVA *gSudExecHook = NULL;

/// @brief  Buffer for fast accessing the current contents of SharedUserData.
static BYTE *gSudBuffer = NULL;

/// @brief  Is set to true when integrity is initialized on SharedUserData signaling that checks can be performed.
static BOOLEAN gSudIntegrityInitialized = FALSE;

/// @brief  Describes a field from KUSER_SHARED_DATA which is protected through integrity.
typedef struct _SHARED_USER_DATA_PROT_FIELD
{
    char        *FieldName;             ///< The name of the KUSER_SHARED_DATA field.
    WORD        FieldOffset;            ///< The offset of the field in the structure.
    /// @brief  The size of the field. Note that this size can be 1, 2, 4, 8 for fields which
    /// are initialized, and can be any size if the field contains only zero values (when ShouldBeZero
    /// is set to TRUE) as long as the field is contained in the same page as the KUSER_SHARED_DATA
    /// structure.
    WORD        FieldSize;
    /// @brief  The number of modifications on the field from the time the protection has been initialized
    /// up until now. It is used for de-activating the protection on the current field when the number of
    /// modifications exceeds a fixed threshold (1000 by default), indicating that the field contains
    /// variable data.
    DWORD       ModifiedCount;
    BOOLEAN     ShouldBeZero;           ///< Set to TRUE if the contents of the field should be always zero.
    BOOLEAN     ShouldCheck;            ///< Set to TRUE if this field should be checked on the next timer tick.
    /// @brief  Set to TRUE after an allowed modification has been made on a field with ShouldBeZero set to TRUE.
    /// This will signal that detection can be made again on the current ShouldBeZero field when, on a future check,
    /// the whole contents of the field is filled with 0. This ensures that we will not give an alert once every
    /// second for a ShouldBeZero field that was modified, and will ensure that, when the field becomes filled with
    /// zero again, the field will be again protected and modifications will be detected.
    BOOLEAN     ReenableOnZero;
    QWORD       OldValue;               ///< The saved value for fields that don't have ShouldBeZero set to TRUE.
} SHARED_USER_DATA_PROT_FIELD, *PSHARED_USER_DATA_PROT_FIELD;

/// @brief  Global array containing the descriptors used for protecting fields inside SharedUserData.
SHARED_USER_DATA_PROT_FIELD gProtFields[] =
{
    {
        .FieldName = "ImageNumber",
        .FieldOffset = 0x2c,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "CryptoExponent",
        .FieldOffset = 0x23c,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "LargePageMinimum",
        .FieldOffset = 0x244,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "AppCompatFlag",
        .FieldOffset = 0x24c,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "NtBuildNumber",
        .FieldOffset = 0x260,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "NtProductType",
        .FieldOffset = 0x264,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProductTypeIsValid",
        .FieldOffset = 0x268,
        .FieldSize = 0x1,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "NativeProcessorArchitecture",
        .FieldOffset = 0x26a,
        .FieldSize = 0x2,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "NtMajorVersion",
        .FieldOffset = 0x26c,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "NtMinorVersion",
        .FieldOffset = 0x270,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures1",
        .FieldOffset = 0x274,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures2",
        .FieldOffset = 0x27c,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures3",
        .FieldOffset = 0x284,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures4",
        .FieldOffset = 0x28c,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures5",
        .FieldOffset = 0x294,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures6",
        .FieldOffset = 0x29c,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures7",
        .FieldOffset = 0x2a4,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ProcessorFeatures8",
        .FieldOffset = 0x2ac,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "KdDebuggerEnabled",
        .FieldOffset = 0x2d4,
        .FieldSize = 0x1,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "MitigationPolicies",
        .FieldOffset = 0x2d5,
        .FieldSize = 0x1,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "SafeBootMode",
        .FieldOffset = 0x2ec,
        .FieldSize = 0x1,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "VirtualizationFlags",
        .FieldOffset = 0x2ed,
        .FieldSize = 0x1,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "TestRetInstruction",
        .FieldOffset = 0x2f8,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "SystemCall",
        .FieldOffset = 0x308,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    // Pads may be used to write a structure for example.
    {
        .FieldName = "SystemCallPad1",
        .FieldOffset = 0x310,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "SystemCallPad2",
        .FieldOffset = 0x318,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "EnclaveFeatureMask1",
        .FieldOffset = 0x36c,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "EnclaveFeatureMask2",
        .FieldOffset = 0x374,
        .FieldSize = 0x8,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ImageFileExecutionOptions",
        .FieldOffset = 0x3a0,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    {
        .FieldName = "ActiveProcessorCount",
        .FieldOffset = 0x3c0,
        .FieldSize = 0x4,
        .ShouldCheck = TRUE
    },

    // Note: this field will be adjusted IntWinSudProtectIntegrity so that it will begin exactly
    // from the end of the KUSER_SHARED_DATA structure.
    {
        .FieldName = "AfterSudRegion",
        .FieldOffset = 0x800,
        .FieldSize = 0x800,
        .ShouldBeZero = TRUE,
        .ShouldCheck = TRUE
    }
};


static void
IntWinSudSendSudExecAlert(
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ BOOLEAN IsKernel,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief  Constructs and sends an #EVENT_EPT_VIOLATION alert which occurred due to an
///         execution in SharedUserData.
///
/// @param[in]  Originator  Depending on the IsKernel parameter, can be #EXCEPTION_KM_ORIGINATOR
///                         or #EXCEPTION_UM_ORIGINATOR. Represents the originator of the execution.
/// @param[in]  Victim      The #EXCEPTION_VICTIM_ZONE representing the victim of the violation.
/// @param[in]  IsKernel    TRUE if the alert occurred in kernel-mode, FALSE for user-mode.
/// @param[in]  Action      The action which was decided by the exception engine.
/// @param[in]  Reason      The reason why the given action has been taken.
///
{
    EVENT_EPT_VIOLATION *pEpt = &gAlert.Ept;
    INTSTATUS status;

    memzero(pEpt, sizeof(*pEpt));

    pEpt->Header.Action = Action;
    pEpt->Header.Reason = Reason;
    pEpt->Header.MitreID = idExploitRemote;

    IntAlertEptFillFromVictimZone(Victim, pEpt);

    IntAlertFillCpuContext(TRUE, &pEpt->Header.CpuContext);

    IntAlertFillWinProcessByCr3(gVcpu->Regs.Cr3, &pEpt->Header.CurrentProcess);

    pEpt->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SUD_EXEC, Reason);

    pEpt->ExecInfo.Rsp = gVcpu->Regs.Rsp;
    pEpt->ExecInfo.Length = gVcpu->Instruction.Length;

    if (IsKernel)
    {
        EXCEPTION_KM_ORIGINATOR *originator = Originator;

        IntAlertEptFillFromKmOriginator(originator, pEpt);
    }
    else
    {
        EXCEPTION_UM_ORIGINATOR *originator = Originator;

        IntAlertFillWinUmModule(originator->Return.Library, &pEpt->Originator.ReturnModule);
        pEpt->ReturnRip = originator->Return.Rip;
    }

    IntAlertFillCodeBlocks(gVcpu->Regs.Rip, gVcpu->Regs.Cr3, TRUE, &pEpt->CodeBlocks);
    IntAlertFillExecContext(0, &pEpt->ExecContext);

    IntAlertFillVersionInfo(&pEpt->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEpt, sizeof(*pEpt));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntWinSudHandleKernelSudExec(
    _In_ QWORD Address,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief  Handles a kernel mode execution inside SharedUserData.
///
/// This function will call the exceptions mechanism, decide if an alert should be sent,
/// and sends it, if it is the case, for the given kernel-mode execution in SharedUserData.
///
/// @param[in]      Address     The physical address on which the execution occurred.
/// @param[in, out] Action      The action which is decided by the exception mechanism and
///                             the current policy.
///
/// @retval #INT_STATUS_SUCCESS     On success.
///
{
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    BOOLEAN exitAfterInformation = FALSE;
    INTRO_ACTION_REASON reason = introReasonUnknown;
    INTSTATUS status;

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed: %08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(NULL,
                                   Address,
                                   gVcpu->Regs.Rip,
                                   introObjectTypeSudExec,
                                   ZONE_EXECUTE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed: %08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_SUD_EXEC, Action, &reason))
    {
        LOG("[SUD-EXEC] An execution on shared user data occured in kernel-mode!\n");

        IntDumpCodeAndRegs(gVcpu->Regs.Rip, Address, &gVcpu->Regs);

        IntWinSudSendSudExecAlert(&originator, &victim, TRUE, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_SUD_EXEC, Action);

    return status;
}


static INTSTATUS
IntWinSudHandleUserSudExec(
    _In_ QWORD Address,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief  Handles an user-mode execution inside SharedUserData.
///
/// This function will call the exceptions mechanism, decide if an alert should be sent,
/// and sends it, if it is the case, for the given user-mode execution in SharedUserData.
///
/// @param[in]      Address     The physical address on which the execution occurred.
/// @param[in, out] Action      The action which is decided by the exception mechanism and
///                             the current policy.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If there doesn't exist a process with the current CR3.
///
{
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    WIN_PROCESS_OBJECT *pProc;
    INTRO_ACTION_REASON reason = introReasonUnknown;
    BOOLEAN exitAfterInformation = FALSE;
    INTSTATUS status;

    pProc = IntWinProcFindObjectByCr3(gVcpu->Regs.Cr3);
    if (NULL == pProc)
    {
        ERROR("[ERROR] No process found with cr3: 0x%016llx, but ring is 3! Will inject #UD!",
              gVcpu->Regs.Cr3);
        return INT_STATUS_NOT_FOUND;
    }

    STATS_ENTER(statsExceptionsUser);

    status = IntExceptUserGetExecOriginator(pProc, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(pProc,
                                   Address,
                                   gVcpu->Regs.Rip,
                                   introObjectTypeSudExec,
                                   ZONE_EXECUTE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }
    if (exitAfterInformation)
    {
        IntExceptUserLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeUm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsUser);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_SUD_EXEC, Action, &reason))
    {
        LOG("[SUD-EXEC] An execution on shared user data occured in user-mode!\n");

        IntDumpCodeAndRegs(gVcpu->Regs.Rip, Address, &gVcpu->Regs);

        IntWinSudSendSudExecAlert(&originator, &victim, FALSE, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_SUD_EXEC, Action);

    return status;
}


static INTSTATUS
IntWinSudHandleSudExec(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Ept callback which handles executions inside SharedUserData.
///
/// This will handle the executions, based on current ring, separately on kernel mode and user mode.
/// For kernel mode executions, if the execution is deemed malicious, we will overwrite the first
/// instruction from the executed area with a RET instruction, so that the execution is returned
/// to the driver which called this region, limiting as much as possible the damage that can be
/// provoked by such an execution, and limiting the possibility of a system crash. However, if the
/// current ring points to an execution in user mode, we will instead inject an UD exception into
/// the guest, trying to crash the process trying the execution, so that we limit the ability of
/// this given process to continue execution.
///
/// @param[in]  Context     User-supplied context. Unused in this case.
/// @param[in]  Hook        The hook object for the given protection. Unused in this case.
/// @param[in]  Address     The physical address on which the violation occurred.
/// @param[out] Action      The #INTRO_ACTION which is decided for the given execution in this handler.
///
/// @retval     #INT_STATUS_SUCCESS     On success
///
{
    INTSTATUS status;
    DWORD ring;
    INFO_UD_PENDING *pending = NULL;
    QWORD currentThread = 0;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);

    *Action = introGuestNotAllowed;

    status = IntGetCurrentRing(gVcpu->Index, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        IntBugCheck();
    }

    STATS_ENTER(statsSudExec);

    if (ring == IG_CS_RING_0)
    {
        status = IntWinSudHandleKernelSudExec(Address, Action);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSudHandleKernelSudExec failed: 0x%08x\n", status);
        }
    }
    else
    {
        status = IntWinThrGetCurrentThread(gVcpu->Index, &currentThread);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
            return status;
        }

        pending = IntUDGetEntry(gVcpu->Regs.Cr3, gVcpu->Regs.Rip, currentThread);
        if (NULL != pending)
        {
            goto cleanup_and_take_action;
        }

        status = IntWinSudHandleUserSudExec(Address, Action);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSudHandleKernelSudExec failed: 0x%08x\n", status);
        }
    }

cleanup_and_take_action:
    if (*Action == introGuestNotAllowed)
    {
        if (ring == IG_CS_RING_0)
        {
            BYTE ret = 0xc3;

            status = IntPhysicalMemWrite(Address, sizeof(ret), &ret);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemWrite failed: 0x%08x\n", status);
            }

            // Force action to introGuestAllowed, in order to force emulation, otherwise we'll end up in an infinite
            // cycle, depending on the hypervisor by forcing it to introGuestRetry. For example, this happens on xen.
            *Action = introGuestAllowed;
        }
        else
        {
            // We are already waiting for the current #UD to get injected.
            if (NULL != pending && gVcpu->CurrentUD == pending)
            {
                goto _skip_inject;
            }

            status = IntInjectExceptionInGuest(VECTOR_UD, 0, NO_ERRORCODE, gVcpu->Index);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntInjectExceptionInGuest failed: 0x%08x\n", status);
            }
            else
            {
                if (NULL == pending)
                {
                    status = IntUDAddToPendingList(gVcpu->Regs.Cr3,
                                                   gVcpu->Regs.Rip,
                                                   currentThread,
                                                   &pending);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntUDAddToPendingList failed: 0x%08x\n", status);
                        return status;
                    }
                }

                gVcpu->CurrentUD = pending;
            }

        _skip_inject:
            *Action = introGuestRetry;
        }
    }

    STATS_EXIT(statsSudExec);

    // Even if the action has been set as allowed by the exceptions mechanism, we'll not remove the hook,
    // as the hook needs to remain established.

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinSudProtectSudExec(
    void
    )
///
/// @brief  Protects SharedUserData against executions by establishing an EPT hook on it.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED     If the hook is already established.
///
{
    INTSTATUS status;

    if (NULL != gSudExecHook)
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    status = IntHookGvaSetHook(gGuest.Mm.SystemCr3,
                               WIN_SHARED_USER_DATA_PTR,
                               PAGE_SIZE,
                               IG_EPT_HOOK_EXECUTE,
                               IntWinSudHandleSudExec,
                               NULL,
                               NULL,
                               0,
                               &gSudExecHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinSudUnprotectSudExec(
    void
    )
///
/// @brief  Removes the execution EPT hook on SharedUserData.
///
/// @retval #INT_STATUS_SUCCESS         On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the hook was not previously established.
///
{
    INTSTATUS status;

    if (NULL == gSudExecHook)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    status = IntHookGvaRemoveHook(&gSudExecHook, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
    }

    return status;
}


static BOOLEAN
IntWinSudFetchFieldCurrentValue(
    _In_ SHARED_USER_DATA_PROT_FIELD *Field,
    _Inout_ QWORD *CurrentValue
    )
///
/// @brief  Fetches the value of the given described field from the global SharedUserData buffer.
///
/// This function should be called only for described fields that have ShouldBeZero set to FALSE.
/// If the field size is not 1, 2, 4 or 8, the function will return FALSE and will not fetch the
/// field value.
///
/// @retval     TRUE    If the value has been succesfully fetched for the given field.
/// @retval     FALSE   Otherwise.
///
{
    QWORD currentValue;

    switch (Field->FieldSize)
    {
        case 1:
            currentValue = gSudBuffer[Field->FieldOffset];
            break;
        case 2:
            currentValue = *(WORD *)&gSudBuffer[Field->FieldOffset];
            break;
        case 4:
            currentValue = *(DWORD *)&gSudBuffer[Field->FieldOffset];
            break;
        case 8:
            currentValue = *(QWORD *)&gSudBuffer[Field->FieldOffset];
            break;
        default:
            return FALSE;
    }

    *CurrentValue = currentValue;

    return TRUE;
}


static void
IntWinSudSendSudIntegrityAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ SHARED_USER_DATA_PROT_FIELD *Field,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief  Completes and sends an alert for a detected SharedUserData modification on a monitored
///         field.
///
/// @param[in]  Victim  The #EXCEPTION_VICTIM_ZONE describing the modified field.
/// @param[in]  Field   The #SHARED_USER_DATA_PROT_FIELD describing the protected field.
/// @param[in]  Action  The action which was taken before deciding to send the alert.
/// @param[in]  Reason  The reason for which the given action has been taken.
///
{
    INTSTATUS status;
    EVENT_INTEGRITY_VIOLATION *pIntViol;

    pIntViol = &gAlert.Integrity;
    memzero(pIntViol, sizeof(*pIntViol));

    pIntViol->Header.Flags |= IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SUD_INTEGRITY, Reason);

    // Force de-activation of ALERT_FLAG_NOT_RING0. We're always in ring0.
    pIntViol->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    pIntViol->Header.Flags |= ALERT_FLAG_ASYNC;

    pIntViol->Header.Action = Action;
    pIntViol->Header.Reason = Reason;
    pIntViol->Header.MitreID = idRootkit;

    pIntViol->Victim.Type = Victim->Object.Type;

    IntAlertFillWinProcess(Victim->Object.Process, &pIntViol->Header.CurrentProcess);

    utf8toutf16(pIntViol->Victim.Name, Field->FieldName, sizeof(pIntViol->Victim.Name) / 2);

    IntAlertFillCpuContext(FALSE, &pIntViol->Header.CpuContext);

    // We can't know from what CPU the write was, but we know where the integrity check failed
    pIntViol->Header.CpuContext.Valid = FALSE;

    pIntViol->BaseAddress = WIN_SHARED_USER_DATA_PTR;
    pIntViol->VirtualAddress = pIntViol->BaseAddress + Field->FieldOffset;
    pIntViol->Size = Field->FieldSize;

    IntAlertFillVersionInfo(&pIntViol->Header);

    IntAlertFillWriteInfo(Victim, &pIntViol->WriteInfo);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViol, sizeof(*pIntViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntWinSudHandleFieldModification(
    _In_ SHARED_USER_DATA_PROT_FIELD *Field,
    _In_ QWORD NewValue
    )
///
/// @brief  This function is called when a modification has been detected on a given field in order to take
///         a decision on the current modification.
///
/// This will call the exception engine in order to verify whether the current modification is excepted or not
/// and based on the current policy and options will decide if an alert should be sent. Depending on the taken
/// action, this function will decide to rewrite the modified field with the old value or to internally
/// acknowledge the new value as the known one, if the modification was deemed legitimate.
///
/// @param[in]  Field       The #SHARED_USER_DATA_PROT_FIELD describing the field on which the modification has 
///                         been detected.
/// @param[in]  NewValue    The new value of the modified field. For ShouldBeZero fields it should be ignored.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    INTSTATUS status;

    STATS_ENTER(statsExceptionsKern);

    originator.Original.NameHash = INITIAL_CRC_VALUE;
    originator.Return.NameHash = INITIAL_CRC_VALUE;

    victim.Object.Type = introObjectTypeSudIntegrity;
    victim.Object.NameHash = Crc32String(Field->FieldName, INITIAL_CRC_VALUE);
    victim.Object.BaseAddress = WIN_SHARED_USER_DATA_PTR;

    // Used just for logging.
    victim.Object.Name = Field->FieldName;
    victim.Integrity.StartVirtualAddress = WIN_SHARED_USER_DATA_PTR;
    victim.Integrity.Offset = Field->FieldOffset;

    victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
    victim.ZoneType = exceptionZoneIntegrity;

    victim.WriteInfo.OldValue[0] = Field->OldValue;

    if (Field->ShouldBeZero)
    {
        // Copy as much as we can (max 64 bytes) from the protected field which should be 0.
        // It should be enough for analysis on the alert. Also we need to copy from the first
        // byte that is non-zero, otherwise we'll most probably just copy some unmodified zero-es
        // from the protected region.
        DWORD startOffset = Field->FieldOffset;
        DWORD copySize;

        for (DWORD i = Field->FieldOffset; i < (DWORD)Field->FieldOffset + Field->FieldSize; i++)
        {
            if (gSudBuffer[i] != 0)
            {
                startOffset = i;
                break;
            }
        }

        copySize = MIN(sizeof(victim.WriteInfo.NewValue), (QWORD)Field->FieldOffset + Field->FieldSize - startOffset);

        memcpy(victim.WriteInfo.NewValue, &gSudBuffer[startOffset], copySize);
    }
    else
    {
        victim.WriteInfo.NewValue[0] = NewValue;
    }

    victim.WriteInfo.AccessSize = Field->FieldSize;

    IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_SUD_INTEGRITY, &action, &reason))
    {
        IntWinSudSendSudIntegrityAlert(&victim, Field, action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_SUD_INTEGRITY, &action);

    if (action == introGuestAllowed)
    {
        if (Field->ShouldBeZero)
        {
            // Not really much we can do, so disable this field so we won't send an alert every second, and re-enable
            // it if at a further check we find the field filled again with zeroes...
            Field->ReenableOnZero = TRUE;
        }
        else
        {
            // Overwrite the old value, so that we don't raise an alert every second for an allowed modification.
            Field->OldValue = NewValue;
        }
    }
    else if (action == introGuestNotAllowed)
    {
        if (Field->ShouldBeZero)
        {
            // The best option would be to just map the page and overwrite the zeroes.
            BYTE *pPage = NULL;

            IntPauseVcpus();

            status = IntVirtMemMap(WIN_SHARED_USER_DATA_PTR, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);

                IntResumeVcpus();

                return status;
            }

            for (DWORD i = Field->FieldOffset; i < (DWORD)Field->FieldOffset + Field->FieldSize; i++)
            {
                pPage[i] = 0;
            }

            IntResumeVcpus();

            IntVirtMemUnmap(&pPage);
        }
        else
        {
            IntPauseVcpus();

            status = IntKernVirtMemWrite(WIN_SHARED_USER_DATA_PTR + Field->FieldOffset,
                                         Field->FieldSize,
                                         &Field->OldValue);

            IntResumeVcpus();

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemWrite failed for gva 0x%016llx: 0x%08x\n",
                      (QWORD)WIN_SHARED_USER_DATA_PTR + Field->FieldOffset, status);
                return status;
            }
        }

    }

    return INT_STATUS_SUCCESS;
}


TIMER_FRIENDLY INTSTATUS
IntWinSudCheckIntegrity(
    void
    )
///
/// @brief  This function checks the integrity of protected fields from SharedUserData, described in #gProtFields.
///
/// For every field in #gProtFields, this function will check whether the internally saved value is equal to the
/// current value. For this purpose, this function will fetch the SharedUserData contents in #gSudBuffer in order
/// to verfiy the new values. For fields that have ShouldBeZero set to TRUE, this function will verify every
/// byte from the described field to be equal to zero. If the ShouldBeZero field has been previously modified
/// and the modification has been allowed, it has the ReenableOnZero flag set, therefore, if a ShouldBeZero field
/// is now filled with zeroes, this function will re-enable the checks on it.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT    If the SharedUserData integrity protection was not yet initialized.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE  If the SharedUserData protection is initialized but the protection
///                                                 flags do not include this protection.
///
{
    INTSTATUS status;

    if (!gSudIntegrityInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SUD_INTEGRITY))
    {
        // Raise an error, this should not be true, gSudIntegrityInitialized should be always set to FALSE
        // if the flag is not given.
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    STATS_ENTER(statsSudIntegrity);

    status = IntKernVirtMemRead(WIN_SHARED_USER_DATA_PTR, PAGE_SIZE, gSudBuffer, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtFields); i++)
    {
        BOOLEAN modified = FALSE;
        QWORD newValue = 0;

        if (!gProtFields[i].ShouldCheck)
        {
            continue;
        }

        if (gProtFields[i].ShouldBeZero)
        {
            BOOLEAN reenable = gProtFields[i].ReenableOnZero;

            if (!UtilIsBufferZero(&gSudBuffer[gProtFields[i].FieldOffset], gProtFields[i].FieldSize))
            {
                if (!gProtFields[i].ReenableOnZero)
                {
                    modified = TRUE;
                }
                else
                {
                    reenable = FALSE;
                }
            }

            // If we didn't find any non-zero values and the ReenableOnZero flag was previously set, then
            // unset it and from now on we will handle as detections the writes over this zone.
            if (reenable)
            {
                gProtFields[i].ReenableOnZero = FALSE;
            }
        }
        else
        {
            if (!IntWinSudFetchFieldCurrentValue(&gProtFields[i], &newValue))
            {
                continue;
            }

            if (gProtFields[i].OldValue != newValue)
            {
                WARNING("[WARNING] At field %s offset 0x%x, value should be 0x%llx but is 0x%llx\n",
                    gProtFields[i].FieldName, gProtFields[i].FieldOffset, gProtFields[i].OldValue, newValue);

                modified = TRUE;
            }
        }

        if (modified)
        {
            status = IntWinSudHandleFieldModification(&gProtFields[i], newValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinSudHandleFieldModification failed: 0x%08x\n", status);
            }

            gProtFields[i].ModifiedCount++;
        }

        // We keep a threshold as a safe guard, as some fields may get often modified and we should not send an alert per second
        // for every modification indefinitely.
        if (gProtFields[i].ModifiedCount > 1000)
        {
            WARNING("[WARNING] Field %s written more than the threshold, will disable!\n", gProtFields[i].FieldName);
            gProtFields[i].ShouldCheck = FALSE;
        }
    }

_cleanup_and_exit:
    STATS_EXIT(statsSudIntegrity);

    return status;
}


INTSTATUS
IntWinSudProtectIntegrity(
    void
    )
///
/// @brief  Initializes the SharedUserData integrity protection.
///
/// This includes allocating the global buffer for SharedUserData contents, fetching the values in the
/// internal states for the current fields and making some checks regarding the field sizes in order to
/// ensure that the internal state for the protected fields is correct.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the protection is already initialized.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the global buffer could not be allocated.
///
{
    INTSTATUS status;

    if (gSudIntegrityInitialized)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    gSudBuffer = HpAllocWithTag(PAGE_SIZE, IC_TAG_SUD_BUFFER);
    if (NULL == gSudBuffer)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntKernVirtMemRead(WIN_SHARED_USER_DATA_PTR, PAGE_SIZE, gSudBuffer, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    for (DWORD i = 0; i < ARRAYSIZE(gProtFields); i++)
    {
        // As _KUSER_SHARED_DATA is variable in size due to increase in size for _XSTATE_CONFIGURATION, we need
        // to adjust the offset and the size of this specific field.
        if (memcmp(gProtFields[i].FieldName, "AfterSudRegion", sizeof("AfterSudRegion")) == 0)
        {
            gProtFields[i].FieldOffset = (WORD)WIN_KM_FIELD(Ungrouped, SharedUserDataSize);
            gProtFields[i].FieldSize = PAGE_SIZE - gProtFields[i].FieldOffset;
        }

        // No need to extract anything, we already know that this needs to be 0.
        if (gProtFields[i].ShouldBeZero)
        {
            continue;
        }

        if (gProtFields[i].FieldOffset + gProtFields[i].FieldSize > PAGE_SIZE || gProtFields[i].FieldSize == 0)
        {
            ERROR("[ERROR] Field %s is invalid, will disable!\n", gProtFields[i].FieldName);
            gProtFields[i].ShouldCheck = FALSE;
            continue;
        }

        if (!IntWinSudFetchFieldCurrentValue(&gProtFields[i], &gProtFields[i].OldValue))
        {
            ERROR("[ERROR] Field %s with size %d is invalid, will disable!\n",
                  gProtFields[i].FieldName, gProtFields[i].FieldSize);
            gProtFields[i].ShouldCheck = FALSE;
        }
    }

    gSudIntegrityInitialized = TRUE;

_cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&gSudBuffer, IC_TAG_SUD_BUFFER);
    }

    return status;
}


INTSTATUS
IntWinSudUnprotectIntegrity(
    void
    )
///
/// @brief  Uninitializes the SharedUserData integrity protection.
///
/// This will de-allocate the global buffer and will set the #gSudIntegrityInitialized boolean to
/// FALSE, so that the next integrity checks will not be made anymore. Note that there is no need
/// to reset the global state at this point, as a future call to #IntWinSudProtectIntegrity will
/// update the old values, and the ShouldBeZero fields that have ReenableOnZero flag set will be
/// monitored on the next integrity check after the protection was re-activated.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     If the protection is already uninitialized.
///
{
    if (!gSudIntegrityInitialized)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    HpFreeAndNullWithTag(&gSudBuffer, IC_TAG_SUD_BUFFER);

    gSudIntegrityInitialized = FALSE;

    return INT_STATUS_SUCCESS;
}
