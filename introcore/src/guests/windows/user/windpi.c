/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windpi.h"
#include "alerts.h"
#include "winprocesshp.h"
#include "winselfmap.h"
#include "winstack.h"
#include "winthread.h"
#include "wintoken.h"
#include "shellcode.h"
#include "winsecdesc.h"

///
/// @file windpi.c
///
/// @brief This file handles Windows Deep Process Inspection checks.
///
/// When a Windows process starts, introcore can perform additional checks that will determine if the process creation
/// should take place or not. The possible DPI checks are defined by the macro #INTRO_OPT_PROT_DPI, but can be enabled
/// separately. This file also contains the implementation for #PROC_OPT_PROT_PREVENT_CHILD_CREATION.
///


///
/// @brief      Process creation callback, used to check if a process creation breaks one of the currently
///             enabled policies.
///
/// The exception mechanism is checked before taken any action. If the action is #introGuestNotAllowed and the
/// reason is not #introReasonAllowedFeedback, the following callbacks are not invoked. This is done because we
/// block the action only once, and sending more than one alert for the same blocked action is confusing. For feedback
/// only we want to keep sending the events, as the user will not see any of them.
///
/// @param[in]  Child       The process that is being created.
/// @param[in]  RealParent  The real parent of the Child process.
/// @param[out] Originator  On success, will contain a pointer to the process that is the originator of the attack.
/// @param[out] Victim      On success, will contain a pointer to the process that is the originator of the attack.
/// @param[out] PcType      On success, will contain the type of the process creation violation, which is one of the
///                         #INTRO_PC_VIOLATION_TYPE, or 0 if this is not a DPI violation.
///
/// @returns    #INT_STATUS_SUCCESS if an alert should be sent; in this case, the other callbacks will be skipped.
///             If no violation was detected, this should be signaled with #INT_STATUS_NOT_NEEDED_HINT, in which case
///             another callback will be tried. If an error is returned, it will be logged and the next callback
///             will be tried.
///
typedef INTSTATUS
(*PFUNC_IntWinDpiProcessCreationHandler)(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    );


__forceinline
static MITRE_ID
IntWinDpiGetDpiMitreId(
    _In_ INTRO_PC_VIOLATION_TYPE Flags
    )
///
/// @brief      Get the MITRE attack technique ID for the given DPI (Deep Process Inspection) flags.
///
/// @param[in]  Flags   The DPI (Deep Process Inspection) flags.
///
/// @retval     The MITRE attack ID.
///
{
    // In theory, we could have multiple DPI flags set (Stolen
    // Token + Debug Flag - for example). In this case we are
    // going to pick the most dangerous type of attack.

    if (INT_PC_VIOLATION_DPI_STOLEN_TOKEN & Flags)
    {
        return idAccessToken;
    }

    if (INT_PC_VIOLATION_DPI_TOKEN_PRIVS & Flags)
    {
        return idAccessToken;
    }

    if (INT_PC_VIOLATION_DPI_PIVOTED_STACK & Flags)
    {
        return idExploitClientExec;
    }

    if (INT_PC_VIOLATION_DPI_DEBUG_FLAG & Flags)
    {
        return idTrustedDevUtil;
    }

    if (INT_PC_VIOLATION_DPI_HEAP_SPRAY & Flags)
    {
        return idExploitClientExec;
    }

    if (INT_PC_VIOLATION_DPI_THREAD_START & Flags)
    {
        return idExploitClientExec;
    }

    if (INT_PC_VIOLATION_DPI_SEC_DESC & Flags)
    {
        return idAccessToken;
    }

    if (INT_PC_VIOLATION_DPI_ACL_EDIT & Flags)
    {
        return idAccessToken;
    }

    LOG("[ERROR] We do not have any known DPI flag set -> Flags:0x%x\n", Flags);
    return 0;
}


static INTSTATUS
IntWinDpiSendProcessCreationViolation(
    _In_ WIN_PROCESS_OBJECT *VictimProc,
    _In_ WIN_PROCESS_OBJECT *OriginatorProc,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ INTRO_PC_VIOLATION_TYPE PcType
    )
///
/// @brief      Send a process creation violation event.
///
/// @param[in]  VictimProc          The victim process.
/// @param[in]  OriginatorProc      The originator process.
/// @param[in]  Action              Taken action.
/// @param[in]  Reason              Reason for the taken reason.
/// @param[in]  PcType              The DPI (Deep Process Inspection) flags.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    EVENT_PROCESS_CREATION_VIOLATION *pEvent;
    DPI_EXTRA_INFO *extraInfo;

    pEvent = &gAlert.ProcessCreation;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = Action;
    pEvent->Header.Reason = Reason;
    pEvent->Header.MitreID = idExecApi;

    pEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_PREVENT_CHILD_CREATION, VictimProc, Reason, 0);

    IntAlertFillCpuContext(TRUE, &pEvent->Header.CpuContext);

    IntAlertFillWinProcessByCr3(pEvent->Header.CpuContext.Cr3,
                                &pEvent->Header.CurrentProcess);

    IntAlertFillVersionInfo(&pEvent->Header);

    IntAlertFillWinProcess(VictimProc, &pEvent->Victim);
    IntAlertFillWinProcess(OriginatorProc, &pEvent->Originator);

    pEvent->PcType = PcType;
    if (pEvent->PcType)
    {
        pEvent->Header.MitreID = IntWinDpiGetDpiMitreId(pEvent->PcType);
    }

    if (pEvent->PcType == INT_PC_VIOLATION_DPI_DEBUG_FLAG)
    {
        extraInfo = &VictimProc->DpiExtraInfo;
    }
    else
    {
        extraInfo = &OriginatorProc->DpiExtraInfo;
    }

    IntAlertFillDpiExtraInfo(extraInfo, pEvent->PcType, VictimProc, &pEvent->DpiExtraInfo);

    status = IntNotifyIntroEvent(introEventProcessCreationViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static __forceinline BOOLEAN
IntWinDpiIsSelf(
    _In_ WIN_PROCESS_OBJECT const *First,
    _In_ WIN_PROCESS_OBJECT const *Second)
{
    if (memcmp(First->Name, Second->Name, IMAGE_BASE_NAME_LEN) == 0)
    {
        return First->MainModuleAddress == Second->MainModuleAddress;
    }

    return FALSE;
}


static INTSTATUS
IntWinDpiHandleNormalCreationRights(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation contradicts the non-DPI process creation policy set by the
///             #PROC_OPT_PROT_PREVENT_CHILD_CREATION protection option.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI flags. Since this checks for a normal process creation violation, this will
///                             always be 0.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(RealParent->ProtectionMask & PROC_OPT_PROT_PREVENT_CHILD_CREATION))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (IntWinDpiIsSelf(Child, RealParent))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    *Originator = Child;
    *Victim = RealParent;
    *PcType = 0;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiStolenToken(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI token steal policy set by #INTRO_OPT_PROT_DPI_TOKEN_STEAL.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI flags. This will either be 0, if no violation was detected, or
///                             #INT_PC_VIOLATION_DPI_STOLEN_TOKEN.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_TOKEN_STEAL))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.TokenStolenFromEprocess)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_STOLEN_TOKEN;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiTokenPrivs(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI token privileges policy set
/// by #INTRO_OPT_PROT_DPI_TOKEN_PRIVS.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI flags. This will either be 0, if no violation was detected, or
///                             #INT_PC_VIOLATION_DPI_TOKEN_PRIVS.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_TOKEN_PRIVS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentHasTokenPrivsAltered)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Here there might be two possible cases:
    // a) The parent has been exploited and, after a LPE, has been put to create some new malicious process.
    // b) The parent has run an exploit in order to gain increased privileges and now runs new processes
    // which normally it should not run.
    // As a) seems the most likely scenario in the wild, we'll let it this way.
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_TOKEN_PRIVS;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiSecDesc(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI security descriptor policy set
/// by #INTRO_OPT_PROT_DPI_SD_ACL (modified security descriptor).
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI flags. This will either be 0, if no violation was detected, or
///                             #INT_PC_VIOLATION_DPI_SEC_DESC.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_SD_ACL))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentHasAlteredSecDescPtr)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // We are going to consider that the child process is the originator (after a successful exploit, the parent process
    // will attempt to launch a "payload" process).
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_SEC_DESC;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiAclEdit(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI security descriptor policy set
/// by #INTRO_OPT_PROT_DPI_SD_ACL (SACL/DACL).
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI flags. This will either be 0, if no violation was detected, or
///                             #INT_PC_VIOLATION_DPI_ACL_EDIT.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_SD_ACL))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentHasEditedAcl)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // We are going to consider that the child process is the originator (after a successful exploit, the parent process
    // will attempt to launch a "payload" process).
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_ACL_EDIT;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiPivotedStack(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI pivoted stack policy set by #INTRO_OPT_PROT_DPI_STACK_PIVOT.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI (Deep Process Inspection) flags. This will either be 0, if no violation
///                             was detected, or #INT_PC_VIOLATION_DPI_PIVOTED_STACK.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_STACK_PIVOT))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentHasPivotedStack)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (IntWinDpiIsSelf(Child, RealParent))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // The real parent is most likely the victim here as it has the stack pivoted, but this may not always
    // mean that it is without sin, as it can end up in this way after a process hollow (in which case
    // the _IntWinProcIsSelf check from above should be removed)
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_PIVOTED_STACK;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiDebug(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI debug flag policy set by #INTRO_OPT_PROT_DPI_DEBUG.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI (Deep Process Inspection) flags. This will either be 0, if no violation
///                             was detected, or #INT_PC_VIOLATION_DPI_DEBUG_FLAG.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_DEBUG))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.DebuggerEprocess)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (IntWinDpiIsSelf(Child, RealParent))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    *Originator = RealParent;
    *Victim = Child;
    *PcType = INT_PC_VIOLATION_DPI_DEBUG_FLAG;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiHeapSpray(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation breaks the DPI heap spray policy set by #INTRO_OPT_PROT_DPI_HEAP_SPRAY.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI (Deep Process Inspection) flags. This will either be 0, if no violation
///                             was detected, or #INT_PC_VIOLATION_DPI_HEAP_SPRAY.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_HEAP_SPRAY))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentHasBeenHeapSprayed)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // It's the same as in the case of pivoted stack.
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_HEAP_SPRAY;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiHandleDpiThreadStart(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Out_ WIN_PROCESS_OBJECT **Originator,
    _Out_ WIN_PROCESS_OBJECT **Victim,
    _Out_ INTRO_PC_VIOLATION_TYPE *PcType
    )
///
/// @brief      Checks if a process creation was triggered from a thread which started executing suspicious code.
///
/// @param[in]  Child           The child process.
/// @param[in]  RealParent      The real parent process.
/// @param[out] Originator      On success, will contain a pointer to the originator process.
/// @param[out] Victim          On success, will contain a pointer to the victim process.
/// @param[out] PcType          The DPI (Deep Process Inspection) flags. This will either be 0, if no violation
///                             was detected, or #INT_PC_VIOLATION_DPI_THREAD_START.
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     Signals that there is no reason to treat this as a malicious action.
/// @retval     #INT_STATUS_SUCCESS             Signals that an alert should be sent.
///
{
    *Originator = NULL;
    *Victim = NULL;
    *PcType = 0;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_THREAD_SHELL))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Child->CreationInfo.ParentThreadSuspicious)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // It's the same as in the case of pivoted stack.
    *Originator = Child;
    *Victim = RealParent;
    *PcType = INT_PC_VIOLATION_DPI_THREAD_START;

    return INT_STATUS_SUCCESS;
}


static QWORD
IntWinDpiGetViolationAddress(
    _In_ INTRO_PC_VIOLATION_TYPE PcType,
    _In_ WIN_PROCESS_OBJECT *Originator,
    _In_ WIN_PROCESS_OBJECT *Victim
    )
///
/// @brief Gets the violation address, sent through Originator in exception mechanism.
///
/// This is used in order to match value code exceptions on #INT_PC_VIOLATION_DPI_HEAP_SPRAY.
///
/// @param[in]  PcType      The #INTRO_PC_VIOLATION_TYPE for which the violation was triggered.
/// @param[in]  Originator  The process which is considered as the originator of the violation.
/// @param[in]  Victim      The process which is considered the victim of the violation.
///
/// @returns    The address at which the violation which triggered the DPI alert occurred.
///
{
    UNREFERENCED_PARAMETER(Victim);

    if (PcType == INT_PC_VIOLATION_DPI_HEAP_SPRAY)
    {
        WORD maxNumberOfHeapVals = 0;
        DWORD maxPageHeapVals = 0;

        for (DWORD val = 0x1; val < HEAP_SPRAY_NR_PAGES; val++)
        {
            QWORD heapVal = (val << 24) | (val << 16) | (val << 8) | val;

            if (Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected)
            {
                return (heapVal & PAGE_MASK) + Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Offset;
            }

            if (Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount >= maxNumberOfHeapVals &&
                Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped)
            {
                maxNumberOfHeapVals = (WORD)Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
                maxPageHeapVals = heapVal & PAGE_MASK;
            }
        }

        // If nothing was detected, there should be a page containing heap values.
        return maxPageHeapVals;
    }
    else if (PcType == INT_PC_VIOLATION_DPI_THREAD_START)
    {
        return Originator->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress;
    }

    return 0;
}


void
IntWinDpiForceFeedbackIfNeeded(
    _In_ INTRO_PC_VIOLATION_TYPE PcType,
    _In_ WIN_PROCESS_OBJECT *Originator,
    _In_ WIN_PROCESS_OBJECT *Victim,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief  Enforces feedback-only alert on the current DPI violation based on different rules.
///
/// For example, we'll check the shellcode flags from #INT_PC_VIOLATION_DPI_HEAP_SPRAY or
/// #INT_PC_VIOLATION_DPI_THREAD_START, if there are any, against the ShemuOptions feedback only
/// flags received through cami, and we'll enforce feedback only if needed.
///
/// @param[in]      PcType      The #INTRO_PC_VIOLATION_TYPE describing the type of the current
///                             violation.
/// @param[in]      Originator  The #WIN_PROCESS_OBJECT considered as originator for the current
///                             violation.
/// @param[in]      Victim      The #WIN_PROCESS_OBJECT considered as victim for the current
///                             violation.
/// @param[in, out] Action      The #INTRO_ACTION which will get overwritten with #introGuestAllowed
///                             if feedback-only is to be enforced.
/// @param[in, out] Reason      The #INTRO_ACTION_REASON which will get overwritten with
///                             #introReasonAllowedFeedback if feedback-only is to be enforced.
///
{
    QWORD scflags = 0;

    UNREFERENCED_PARAMETER(Victim);

    switch (PcType)
    {
        case INT_PC_VIOLATION_DPI_HEAP_SPRAY:
            // Since we will break on the first page which is detected through shemu, we won't keep a per-page
            // shellcode flags, but rather the flags of the first detected page.
            scflags = Originator->DpiExtraInfo.DpiHeapSprayExtraInfo.ShellcodeFlags;
            break;
        case INT_PC_VIOLATION_DPI_THREAD_START:
            scflags = Originator->DpiExtraInfo.DpiThreadStartExtraInfo.ShellcodeFlags;
            break;
        default:
            return;
    }

    // The detection may have been given due to something else (e.g. on heap spray due to heap vals).
    if (scflags == 0)
    {
        return;
    }

    // Shellcode flags (as set by the shellcode emulator) may be overriden via CAMI. A flag marked for feedback
    // will cause the alert to be logged & sent, but no actual detection will appear. Note that we force feedback
    // for shellcode flags if and only if all the reported flags are marked as feedback. If there is a single
    // shellcode flag set that is not feedback, a normal detection will be generated.
    if ((scflags & gGuest.ShemuOptions.Feedback) != 0 &&
        (scflags & ~gGuest.ShemuOptions.Feedback) == 0)
    {
        LOG("Current scflags 0x%016llx shemu feedback 0x%016llx, will force feedback!\n", scflags, gGuest.ShemuOptions.Feedback);
        *Action = introGuestAllowed;
        *Reason = introReasonAllowedFeedback;
    }
}


INTRO_ACTION
IntWinDpiCheckCreation(
    _In_ WIN_PROCESS_OBJECT *Child,
    _In_ WIN_PROCESS_OBJECT *RealParent
    )
///
/// @brief      Analyzes all the process creations rules in order to decided if the process creation
/// should be allowed or not.
///
/// This function is responsible for analyzing if the the process creation respects all the activated DPI (Deep Process
/// Inspection) rules such as: "Normal" Creation Rights (the parent has the #PROC_OPT_PROT_PREVENT_CHILD_CREATION
/// flag set), stolen token (the child process stole a security token), pivoted stack (the parent process has a pivoted
/// stack), debug (the child process is being debugged) and  heap spray (the parent process has been heap sprayed).
///
/// @param[in]  Child            The child process.
/// @param[in]  RealParent       The real parent process.
///
/// @returns    The action to be taken.
///
{
    INTRO_ACTION retAction = introGuestAllowed;

    // The order here matters:
    //  1. Check for creations that violate the PROC_OPT_PROT_PREVENT_CHILD_CREATION flag because if that one is
    // set it means that someone asked us to block process creations from a specific process
    //  2. Check for stolen tokens
    //  3. Check for token privileges altered in a malicious way.
    //  4. Check for pivoted stack
    //  5. Check for a debug flag
    //  6. Check for a heap spray
    //  7. Check if a thread was created on a zone considered suspicious
    //  8. Check for altered security descriptor
    //  9. Check for edited ACL (SACL/DACL)
    // The first check that generates an alert sends it and we don't do the other checks (unless in beta/feedback only,
    // when we want to see everything)
    PFUNC_IntWinDpiProcessCreationHandler handlers[] =
    {
        IntWinDpiHandleNormalCreationRights,
        IntWinDpiHandleDpiStolenToken,
        IntWinDpiHandleDpiTokenPrivs,
        IntWinDpiHandleDpiPivotedStack,
        IntWinDpiHandleDpiDebug,
        IntWinDpiHandleDpiHeapSpray,
        IntWinDpiHandleDpiThreadStart,
        IntWinDpiHandleDpiSecDesc,
        IntWinDpiHandleDpiAclEdit
    };

    for (DWORD i = 0; i < ARRAYSIZE(handlers); i++)
    {
        PFUNC_IntWinDpiProcessCreationHandler handler = handlers[i];
        INTSTATUS status;
        EXCEPTION_UM_ORIGINATOR originator = { 0 };
        EXCEPTION_VICTIM_ZONE victim = { 0 };
        WIN_PROCESS_OBJECT *procOrig = NULL;
        WIN_PROCESS_OBJECT *procVictim = NULL;
        INTRO_ACTION action;
        INTRO_ACTION_REASON reason;
        INTRO_PC_VIOLATION_TYPE pcType;
        QWORD protFlag;
        QWORD address;

        action = introGuestNotAllowed;
        reason = introReasonInternalError;

        status = handler(Child, RealParent, &procOrig, &procVictim, &pcType);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Process creation violation callback %d failed: 0x%08x\n", i, status);
            continue;
        }
        else if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            // This handler does not apply in this case, go to the next one
            continue;
        }

        address = IntWinDpiGetViolationAddress(pcType, procOrig, procVictim);

        status = IntExceptUserGetOriginator(procOrig, FALSE, address, NULL, &originator);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptUserGetOriginator failed: 0x%08x\n", status);
            goto _send_alert;
        }

        status = IntExceptGetVictimProcessCreation(procVictim,
                                                   pcType ? introObjectTypeProcessCreationDpi :
                                                            introObjectTypeProcessCreation,
                                                   &victim);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptGetVictimProcessCreation failed: 0x%08x\n", status);
            goto _send_alert;
        }

        originator.PcType = pcType;

        IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventProcessCreationViolation);

_send_alert:
        protFlag = pcType ? INTRO_OPT_PROT_DPI : PROC_OPT_PROT_PREVENT_CHILD_CREATION;

        IntWinDpiForceFeedbackIfNeeded(pcType, procOrig, procVictim, &action, &reason);

        if (IntPolicyCoreTakeAction(protFlag, &action, &reason))
        {
            status = IntWinDpiSendProcessCreationViolation(procVictim, procOrig, action, reason, pcType);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcSendProcessCreationViolation failed with status: 0x%08x.\n", status);
            }

            IntPolicyCoreForceBetaIfNeeded(protFlag, &action);
        }

        // Keep the highest action as the final action
        retAction = MAX(retAction, action);
        if (introGuestNotAllowed == action &&
            reason != introReasonAllowedFeedback)    // We want to keep going if this is a feedback only alert
        {
            break;
        }
    }

    return retAction;
}


static INTSTATUS
IntWinDpiGetProcessDebugFlag(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD DebugHandle
    )
///
/// @brief      Determines if the process is being debugged and sets the #WIN_PROCESS_OBJECT.CreationInfo field
///             debugger information to the process that is the debugger.
///
/// It is worth noting the way the debug rights are inherited on Windows. If a process creates another process with
/// the DEBUG_PROCESS flag passed to a creation process API, the parent will debug the newly created process and
/// all the processes it creates, unless the chain is broken when one of the created processes becomes a debugger
/// for another process. If DEBUG_ONLY_THIS_PROCESS is used, only the child process is debugged.
/// See https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags for details.
/// We have to take this into account when determining the process that is the debugger. If the PspInsertProcess
/// API receives a non NULL debug handle parameter, that means that the real parent is the actual debugger. If not,
/// we need to look at the current thread's attached process and figure it out from there. If the NoInheritDebug flag
/// (#winKmFieldEprocessFlagsNoDebugInherit) is not set, and the debug port field (#winKmFieldProcessDebugPort) from
/// the _EPROCESS is non NULL, the process is debugged by whoever debugs the attached process.
///
/// @param[in]  Process         The process object.
/// @param[in]  DebugHandle     The debug handle (explained within the function implementation).
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the debugger EPROCESS was not found inside the internal structures.
///
{
    INTSTATUS status;
    QWORD currentThread = 0;
    QWORD attachedEprocess = 0;
    QWORD flags = 0;
    QWORD debugPort = 0;
    WIN_PROCESS_OBJECT *attachedProc = NULL;

    // From IDA: if the fifth parameter (or fourth on windows 7) is a valid handle, then the current process
    // is debugged by the caller to PspInsertProcess (which will be the Real Parent Process in this case).
    if (DebugHandle)
    {
        // The debugger is the real parent process.
        Process->CreationInfo.DebuggerEprocess = Process->RealParentEprocess;
        return INT_STATUS_SUCCESS;
    }

    status = IntWinThrGetCurrentThread(gVcpu->Index, &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemRead(currentThread + WIN_KM_FIELD(Thread, AttachedProcess),
                                gGuest.WordSize,
                                &attachedEprocess,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemRead(attachedEprocess + WIN_KM_FIELD(Process, Flags),
                                gGuest.WordSize,
                                &flags,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemRead(attachedEprocess + WIN_KM_FIELD(Process, DebugPort),
                                gGuest.WordSize,
                                &debugPort,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    attachedProc = IntWinProcFindObjectByEprocess(attachedEprocess);
    if (NULL == attachedProc)
    {
        ERROR("[ERROR] Attached process with EPROCESS: 0x%016llx is NULL!\n", attachedEprocess);
        return INT_STATUS_NOT_FOUND;
    }

    // From IDA: If the attached process has the NoInheritDebug flag NOT set (flag 2) and has a debug port object set,
    // then the process inherits the debug port object from the attached process. In this case, the debugger for the
    // current process is identical to the debugger of the attached process.
    if (debugPort && (flags & WIN_KM_FIELD(EprocessFlags, NoDebugInherit)) == 0)
    {
        // The debugger is the attached process's debugger.
        Process->CreationInfo.DebuggerEprocess = attachedProc->CreationInfo.DebuggerEprocess;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidatePivotedStack(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_opt_ WIN_PROCESS_OBJECT *RealParent
    )
///
/// @brief      Determines if the parent process has a pivoted stack.
///
/// @param[in]  Process         The child process.
/// @param[in]  RealParent      The real parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD userRsp = 0;
    DWORD segCs = 0;
    BOOLEAN fallback = TRUE;
    BOOLEAN isPivotedWow64 = FALSE;

    // We only fallback to stack-parsing for trap frame if the current process is not a
    // system one and his parent is not the System process.
    if (RealParent)
    {
        fallback = !Process->SystemProcess && RealParent->Pid != 4;
    }

    status = IntWinStackUserTrapFrameGetGeneric(&userRsp, &segCs, fallback, &Process->DpiExtraInfo);
    if (!INT_SUCCESS(status))
    {
        // If we fail to get the TrapFrame for a system process creation or when the parent has pid 4
        // or we choose to skip the check operation for another reason
        // we will consider that the stack isn't pivoted
        if (!fallback || INT_STATUS_NOT_NEEDED_HINT == status)
        {
            Process->CreationInfo.ParentHasPivotedStack = FALSE;

            status = INT_STATUS_SUCCESS;
        }
        else
        {
            ERROR("[ERROR] IntWinStackUserTrapFrameGetGeneric failed: 0x%08x\n", status);
        }

        return status;
    }
    else if (INT_STATUS_NOT_NEEDED_HINT == status)
    {
        return status;
    }

    if (NULL != RealParent && RealParent->Wow64Process)
    {
        status = IntWinStackWow64CheckIsPivoted(Process, RealParent, &Process->DpiExtraInfo);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinStackWow64CheckIsPivoted failed: 0x%08x\n", status);
        }

        isPivotedWow64 = Process->CreationInfo.ParentHasPivotedStack;
        goto _skip_check_64;
    }

    status = IntWinStackUserCheckIsPivoted(userRsp, segCs, FALSE, &Process->DpiExtraInfo,
                                           &Process->CreationInfo.ParentHasPivotedStack);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinStackUserCheckIsPivoted failed: 0x%08x.\n", status);
        return status;
    }
    else if (Process->CreationInfo.ParentHasPivotedStack)
    {
        WARNING("[WARNING] Process 0x%016llx created with pivoted stack\n", Process->EprocessAddress);
    }

_skip_check_64:
    Process->CreationInfo.ParentHasPivotedStack = Process->CreationInfo.ParentHasPivotedStack || isPivotedWow64;

    return status;
}


static INTSTATUS
IntWinDpiValidateParentProcessToken(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the child process stole the security token from any other process.
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    WIN_PROCESS_OBJECT *pStolenFrom;

    if (IntWinTokenPtrIsStolen(Parent, TRUE, &pStolenFrom, NULL, NULL))
    {
        Process->CreationInfo.TokenStolenFromEprocess = pStolenFrom->EprocessAddress;
        Process->DpiExtraInfo.DpiStolenTokenExtraInfo.StolenFromEprocess = pStolenFrom->EprocessAddress;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidateParentSecDesc(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the parent process has a an altered security descriptor pointer.
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    static BYTE securityDescriptorBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];
    WIN_PROCESS_OBJECT *pStolenFrom = NULL;
    INTSTATUS status;
    DWORD totalSize = 0;
    QWORD oldValue = 0;
    QWORD newValue = 0;
    ACL *sacl = NULL;
    ACL *dacl = NULL;

    memset(securityDescriptorBuffer, 0, INTRO_SECURITY_DESCRIPTOR_SIZE);

    if (IntWinSDIsSecDescPtrAltered(Parent, &pStolenFrom, &oldValue, &newValue))
    {
        Process->CreationInfo.ParentHasAlteredSecDescPtr = TRUE;

        Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.SecDescStolenFromEproc =
            pStolenFrom ? pStolenFrom->EprocessAddress : 0;
        Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.NewPtrValue = newValue;
        Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.OldPtrValue = oldValue;

        status = IntWinSDReadSecDesc(newValue,
                                     INTRO_SECURITY_DESCRIPTOR_SIZE,
                                     securityDescriptorBuffer,
                                     &totalSize,
                                     &sacl,
                                     &dacl);
        if (INT_SUCCESS(status))
        {
            if (sacl)
            {
                memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl, sacl, sizeof(ACL));
            }

            if (dacl)
            {
                memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl, dacl, sizeof(ACL));
            }
        }
        
        memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl, &Parent->SecurityDescriptor.Sacl, sizeof(ACL));
        memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl, &Parent->SecurityDescriptor.Dacl, sizeof(ACL));
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidateParentAclEdit(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the parent process has a an altered ACL (SACL/DACL).
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    static BYTE securityDescriptorBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];
    DWORD totalSize;
    ACL *sacl = NULL;
    ACL *dacl = NULL;

    memset(securityDescriptorBuffer, 0, INTRO_SECURITY_DESCRIPTOR_SIZE);

    if (IntWinSDIsAclEdited(Parent, INTRO_SECURITY_DESCRIPTOR_SIZE, securityDescriptorBuffer, &totalSize, &sacl, &dacl))
    {
        Process->CreationInfo.ParentHasEditedAcl = TRUE;

        if (sacl)
        {
            memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl, sacl, sizeof(ACL));
        }

        if (dacl)
        {
            memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl, dacl, sizeof(ACL));
        }

        memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl, &Parent->SecurityDescriptor.Sacl, sizeof(ACL));
        memcpy(&Parent->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl, &Parent->SecurityDescriptor.Dacl, sizeof(ACL));
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidateTokenPrivs(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the parent process token privileges have not been altered in a malicious way.
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    BOOLEAN presentIncreased = FALSE, enabledIncreased = FALSE;
    QWORD present = 0, enabled = 0;

    status = IntWinTokenCheckCurrentPrivileges(Parent,
                                               Parent->OriginalTokenPtr,
                                               FALSE,
                                               &presentIncreased,
                                               &enabledIncreased,
                                               &present,
                                               &enabled);
    if (!INT_SUCCESS(status))
    {
        if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
        {
            // Don't propagate the error, just warn it, as it is benign.
            WARNING("[WARNING] IntWinTokenCheckCurrentPrivileges failed: 0x%08x\n", status);
            return INT_STATUS_SUCCESS;
        }

        return status;
    }

    if (presentIncreased || enabledIncreased || Parent->PrivsChangeDetected)
    {
        Process->CreationInfo.ParentHasTokenPrivsAltered = TRUE;

        Process->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldPresent = Parent->OriginalPresentPrivs;
        Process->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldEnabled = Parent->OriginalEnabledPrivs;
        Process->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewPresent = present;
        Process->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewEnabled = enabled;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidateHeapSpray(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the parent process has been heap sprayed.
///
/// @param[in, out] Process         The child process.
/// @param[in]      Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    DWORD totalHeapValCnt = 0;
    DWORD totalMappedPages = 0;

    if (gGuest.Guest64 && !Parent->Wow64Process)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    for (DWORD val = 0x1; val <= HEAP_SPRAY_NR_PAGES; val++)
    {
        DWORD heapVal = (val << 24) | (val << 16) | (val << 8) | val;
        BYTE *mappedBytes;
        WORD heapValCnt = 0;
        BOOLEAN foundFirstNops = FALSE;
        DWORD firstNopOccurrence = 0;
        IG_ARCH_REGS regs = { 0 };
        QWORD shflags = 0;
        VA_TRANSLATION tr = { 0 };

        status = IntTranslateVirtualAddressEx(heapVal & PAGE_MASK, Parent->Cr3, 0, &tr);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        if (!(tr.Flags & PT_P))
        {
            continue;
        }

        // We can safely mark it as mapped at this point.
        Process->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped = 1;

        if (!tr.IsExecutable)
        {
            continue;
        }

        status = IntVirtMemMap(heapVal & PAGE_MASK, PAGE_SIZE, Parent->Cr3, 0, &mappedBytes);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        Process->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Executable = tr.IsExecutable;

        totalMappedPages++;

        for (DWORD i = 0; i < PAGE_SIZE; i++)
        {
            if (i % 4 == 0)
            {
                if (((DWORD *)mappedBytes)[i / 4] == heapVal)
                {
                    heapValCnt++;
                    totalHeapValCnt++;
                }
            }

            if (mappedBytes[i] == 0x90 && !foundFirstNops)
            {
                if (i > 0 && mappedBytes[i - 1] == 0x90)
                {
                    firstNopOccurrence = i;
                    foundFirstNops = TRUE;
                }
            }
        }

        IntVirtMemUnmap(&mappedBytes);

        Process->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount = heapValCnt;

        // For now a sign of heap spraying is that at least a quarter of the page is filled
        // with the value that we mapped.
        if (heapValCnt >= PAGE_SIZE / 16)
        {
            Process->CreationInfo.ParentHasBeenHeapSprayed = TRUE;
            break;
        }

        // At this point, if there was not any nop sequence found from where to start the emulation
        // the firstNopOccurrence variable will be equal to 0. We'll start the emulation from the
        // beginning of the page, as the shellcode might have spawned on multiple pages.

        regs.Rip = (heapVal & PAGE_MASK) + firstNopOccurrence;
        regs.Cr3 = Parent->Cr3;
        // Dummy value, so there would not be underflows if the stack is 0 and some instruction
        // accesses something on the stack, behind RSP.
        regs.Rsp = 0x10000;

        status = IntShcIsSuspiciousCode((heapVal & PAGE_MASK) + firstNopOccurrence,
                                        tr.PhysicalAddress,
                                        IG_CS_TYPE_32B,
                                        &regs,
                                        &shflags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntShcIsSuspiciousCode failed: 0x%08x\n", status);
            return status;
        }

        if (shflags != 0)
        {
            Process->DpiExtraInfo.DpiHeapSprayExtraInfo.ShellcodeFlags = shflags;
            Process->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected = 1;
            Process->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Offset = firstNopOccurrence;
            Process->CreationInfo.ParentHasBeenHeapSprayed = TRUE;
            // There's no point in continuing, other than statistics.
            break;
        }

    }

    // Very heuristically: if we have mapped 5 pages and we found at least 500 heap values, then we consider
    // it was heap sprayed.
    if (totalMappedPages > 5 && totalHeapValCnt > 500)
    {
        Process->CreationInfo.ParentHasBeenHeapSprayed = TRUE;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDpiValidateThreadStart(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Determines if the current thread from the parent process has been started
///             in order to execute some suspicious code which led to the current process
///             creation.
///
/// @param[in, out] Process         The child process.
/// @param[in]      Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    QWORD thread = 0;
    QWORD startAddress = 0;
    IG_ARCH_REGS regs = { 0 };
    IG_CS_TYPE csType;
    QWORD gpa = 0;
    QWORD scflags = 0;

    if (Process->IsAgent)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntWinThrGetCurrentThread(gVcpu->Index, &thread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemFetchWordSize(thread + WIN_KM_FIELD(Thread, Win32StartAddress), &startAddress);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
        return status;
    }

    status = IntTranslateVirtualAddress(startAddress, Parent->Cr3, &gpa);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntTranslateVirtualAddress failed for 0x%016llx: 0x%08x\n", startAddress, status);

        // If the page has been swapped out, don't propagate the error.
        if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
        {
            return INT_STATUS_SUCCESS;
        }

        return status;
    }

    csType = Parent->Wow64Process || !gGuest.Guest64 ? IG_CS_TYPE_32B : IG_CS_TYPE_64B;

    regs.Rip = startAddress;
    regs.Cr3 = Parent->Cr3;
    // Dummy value, so there would not be underflows if the stack is 0 and some instruction
    // accesses something on the stack, behind RSP.
    regs.Rsp = 0x10000;

    status = IntShcIsSuspiciousCode(startAddress, gpa, csType, &regs, &scflags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntShcIsSuspiciousCode failed: 0x%08x\n", status);
        return status;
    }

    if (scflags != 0)
    {
        VAD vad = { 0 };
        QWORD vadroot = 0;

        // If we're in an imaged mapped vad, don't give a detection. But if we failed to get the vad, then
        // we won't know for sure, and better give a detection in this case.
        status = IntKernVirtMemFetchWordSize(Parent->EprocessAddress + WIN_KM_FIELD(Process, VadRoot), &vadroot);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
            goto _detect;
        }

        status = IntWinVadFetchByRange(vadroot, startAddress & PAGE_MASK, startAddress & PAGE_MASK, &vad);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadFetchByRange failed: 0x%08x\n", status);
            goto _detect;
        }

        if (vad.VadType == VadImageMap)
        {
            goto _exit;
        }

_detect:
        Process->DpiExtraInfo.DpiThreadStartExtraInfo.ShellcodeFlags = scflags;
        Process->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress = startAddress;
        Process->CreationInfo.ParentThreadSuspicious = TRUE;
    }

_exit:
    return INT_STATUS_SUCCESS;
}


static __forceinline BOOLEAN
IntWinDpiIsDpiWhiteListed(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief      Used to whitelist some DPI (Deep Process Inspection) corner cases.
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    // We'll let werfault to be created if the parent process had an exception.
    if (Process->NameHash == 0x56d1611d && // werfault.exe
        Parent->LastException != 0)
    {
        return TRUE;
    }

    // Add there any other cases on which DPI wouldn't need to be checked in the future

    return FALSE;
}


void
IntWinDpiGatherDpiInfo(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *Parent,
    _In_ QWORD DebugHandle
    )
///
/// @brief      Gathers all the necessary DPI (Deep Process Inspection) information that will later be used to decide
/// if the process creation should be allowed or not.
///
/// @param[in]  Process         The child process.
/// @param[in]  Parent          The parent process.
/// @param[in]  DebugHandle     The debug handle.
///
{
    if (IntWinDpiIsDpiWhiteListed(Process, Parent))
    {
        return;
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_DEBUG)
    {
        STATS_ENTER(statsDpiDebugFlag);

        INTSTATUS status = IntWinDpiGetProcessDebugFlag(Process, DebugHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcGetProcessDebugFlag failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiDebugFlag);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_STACK_PIVOT)
    {
        // We don't check the stack of the system process.
        if (__likely(Process->Pid != 4))
        {
            STATS_ENTER(statsDpiStackPivot);

            INTSTATUS status = IntWinDpiValidatePivotedStack(Process, Parent);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcValidatePivotedStack failed: 0x%08x\n", status);
            }

            STATS_EXIT(statsDpiStackPivot);
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_TOKEN_STEAL)
    {
        STATS_ENTER(statsDpiStealToken);

        INTSTATUS status = IntWinDpiValidateParentProcessToken(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcValidateCreatedProcessToken failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiStealToken);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_TOKEN_PRIVS)
    {
        STATS_ENTER(statsDpiTokenPrivs);

        INTSTATUS status = IntWinDpiValidateTokenPrivs(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDpiValidateTokenPrivs failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiTokenPrivs);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_HEAP_SPRAY)
    {
        STATS_ENTER(statsDpiHeapSpray);

        INTSTATUS status = IntWinDpiValidateHeapSpray(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcValidateHeapSpray failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiHeapSpray);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_THREAD_SHELL)
    {
        STATS_ENTER(statsDpiThreadStart);

        INTSTATUS status = IntWinDpiValidateThreadStart(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDpiValidateThreadStart failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiThreadStart);
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_DPI_SD_ACL)
    {
        STATS_ENTER(statsDpiSdAcl);

        INTSTATUS status = IntWinDpiValidateParentSecDesc(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDpiValidateParentSecDesc failed: 0x%08x\n", status);
        }

        status = IntWinDpiValidateParentAclEdit(Process, Parent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDpiValidateParentAcl failed: 0x%08x\n", status);
        }

        STATS_EXIT(statsDpiSdAcl);
    }
}
