/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "scan_engines.h"
#include "guests.h"
#include "alerts.h"

///
/// @file scan_engines.c
///
/// @brief This file handles possibly malicious code executions (sending notifications to the scan engines).
///
/// Introcore may request the AV engines to scan a possibly malicious code execution (if the internal logic did
/// not detect a violation). The scan is done in an asynchronous fashion - data is gathered and sent to the engines
/// and then the execution resumes - the scan engines will invoke a callback (#IntHandleExecCallback) providing their
/// scan result.
///

static void
IntEngCopyArchRegsToIntroGprs(
    _In_ PIG_ARCH_REGS ArchRegs,
    _Out_ PINTRO_GPRS IntroGprs
    )
///
/// @brief Obtains an #INTRO_GPRS structure from an #IG_ARCH_REGS structure.
///
/// @param[in]  ArchRegs    The architecture registers.
/// @param[out] IntroGprs   The general purpose registers.
///
{
    IntroGprs->RegRax = ArchRegs->Rax;
    IntroGprs->RegRcx = ArchRegs->Rcx;
    IntroGprs->RegRdx = ArchRegs->Rdx;
    IntroGprs->RegRbx = ArchRegs->Rbx;
    IntroGprs->RegRsp = ArchRegs->Rsp;
    IntroGprs->RegRbp = ArchRegs->Rbp;
    IntroGprs->RegRsi = ArchRegs->Rsi;
    IntroGprs->RegRdi = ArchRegs->Rdi;
    IntroGprs->RegR8 = ArchRegs->R8;
    IntroGprs->RegR9 = ArchRegs->R9;
    IntroGprs->RegR10 = ArchRegs->R10;
    IntroGprs->RegR11 = ArchRegs->R11;
    IntroGprs->RegR12 = ArchRegs->R12;
    IntroGprs->RegR13 = ArchRegs->R13;
    IntroGprs->RegR14 = ArchRegs->R14;
    IntroGprs->RegR15 = ArchRegs->R15;
    IntroGprs->RegFlags = ArchRegs->Flags;
    IntroGprs->RegRip = ArchRegs->Rip;
    IntroGprs->RegCr2 = ArchRegs->Cr2;
    IntroGprs->RegDr7 = ArchRegs->Dr7;
}


static void
IntEngCopyIntroGprsToArchRegs(
    _In_ PINTRO_GPRS IntroGprs,
    _Out_ PIG_ARCH_REGS ArchRegs
    )
///
/// @brief Obtains an #IG_ARCH_REGS structure from an #INTRO_GPRS structure.
///
/// @param[in]  IntroGprs   The general purpose registers.
/// @param[out] ArchRegs    The architecture registers.
///
{
    ArchRegs->Rax = IntroGprs->RegRax;
    ArchRegs->Rcx = IntroGprs->RegRcx;
    ArchRegs->Rdx = IntroGprs->RegRdx;
    ArchRegs->Rbx = IntroGprs->RegRbx;
    ArchRegs->Rsp = IntroGprs->RegRsp;
    ArchRegs->Rbp = IntroGprs->RegRbp;
    ArchRegs->Rsi = IntroGprs->RegRsi;
    ArchRegs->Rdi = IntroGprs->RegRdi;
    ArchRegs->R8 = IntroGprs->RegR8;
    ArchRegs->R9 = IntroGprs->RegR9;
    ArchRegs->R10 = IntroGprs->RegR10;
    ArchRegs->R11 = IntroGprs->RegR11;
    ArchRegs->R12 = IntroGprs->RegR12;
    ArchRegs->R13 = IntroGprs->RegR13;
    ArchRegs->R14 = IntroGprs->RegR14;
    ArchRegs->R15 = IntroGprs->RegR15;
    ArchRegs->Flags = IntroGprs->RegFlags;
    ArchRegs->Rip = IntroGprs->RegRip;
    ArchRegs->Cr2 = IntroGprs->RegCr2;
    ArchRegs->Dr7 = IntroGprs->RegDr7;
}


static INTSTATUS
IntEngDumpCodeAndRegs(
    _In_ PENG_NOTIFICATION_CODE_EXEC ExecNotification
    )
///
/// @brief Dump the malicious code and registers (used when a malicious code execution is detected).
///
/// When a malicious code execution is detected by the scan engines, this function will dump (log) the page
/// containing the malicious code and the values of the registers.
///
/// @param[in]  ExecNotification   The engine execution notification.
///
{
    DWORD offset, csType;
    IG_ARCH_REGS archRegs = { 0 };
    BYTE *pPage;

    offset = ExecNotification->ExecutionData.ExecContext.Registers.RegRip & PAGE_OFFSET;
    csType = ExecNotification->ExecutionData.Code64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B;
    pPage = ExecNotification->ExecutionData.ExecContext.RipCode;

    IntEngCopyIntroGprsToArchRegs(&ExecNotification->ExecutionData.ExecContext.Registers, &archRegs);
    IntDumpCode(pPage, offset, csType, &archRegs);
    IntDumpArchRegs(&archRegs);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntEngSendExecViolation(
    _In_ PENG_NOTIFICATION_CODE_EXEC ExecNotification
    )
///
/// @brief Send an #EVENT_ENGINES_DETECTION_VIOLATION event to the integrator (a malicious code execution
/// was detected by the scan engines).
///
/// @param[in]  ExecNotification   The engine execution notification.
///
{
    INTSTATUS status;
    EVENT_ENGINES_DETECTION_VIOLATION *pEvent;
    INTRO_ACTION_REASON reason;

    pEvent = &gAlert.EngineDetection;
    memzero(pEvent, sizeof(*pEvent));

    reason = introReasonAllowedFeedback;

    pEvent->Type = introEngineNotificationCodeExecution;

    pEvent->Header.Action = ExecNotification->Header.RequestedAction;
    pEvent->Header.Reason = reason;

    pEvent->Header.Flags = IntAlertProcGetFlags(0, NULL, reason, ALERT_FLAG_FROM_ENGINES);
    pEvent->Header.MitreID = idExploitClientExec;

    // fill up context we had available at the moment of execution
    memcpy(&pEvent->ExecViolation, &ExecNotification->ExecutionData, sizeof(INTRO_EXEC_DATA));

    memcpy(&pEvent->DetectionName[0], &ExecNotification->Header.DetectionName[0], ALERT_MAX_DETECTION_NAME);
    pEvent->DetectionName[ALERT_MAX_DETECTION_NAME - 1] = 0;
    memcpy(&pEvent->EnginesVersion[0], &ExecNotification->Header.EnginesVersion[0], ALERT_MAX_ENGINES_VERSION - 1);

    memcpy(&pEvent->Header.CurrentProcess, &ExecNotification->ExecutionData.Process, sizeof(INTRO_PROCESS));

    status = IntNotifyIntroEvent(introEventEnginesDetectionViolation,
                                 pEvent,
                                 sizeof(EVENT_ENGINES_DETECTION_VIOLATION));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntEngFillExecDetails(
    _In_ PIG_ARCH_REGS Registers,
    _Out_ PENG_NOTIFICATION_CODE_EXEC ExecNotification
    )
///
/// @brief Fill the execution details inside the #ENG_NOTIFICATION_CODE_EXEC structure.
///
/// Fill execution details such as OS type, code32/64 and registers.
///
/// @param[in]  Registers           The architecture registers.
/// @param[out] ExecNotification    The engine execution notification.
///
{
    INTSTATUS status;
    DWORD csType;

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == ExecNotification)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    ExecNotification->Header.Type = introEngineNotificationCodeExecution;
    ExecNotification->Header.OsType = gGuest.OSType;

    status = IntGetCurrentMode(gVcpu->Index, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    ExecNotification->ExecutionData.Code64 = IG_CS_TYPE_64B == csType;

    // Don't memcpy, as modifying one structure could lead to bad things...
    IntEngCopyArchRegsToIntroGprs(Registers, &ExecNotification->ExecutionData.ExecContext.Registers);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixEngExecSendNotification(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ PIG_ARCH_REGS Registers,
    _In_ PINTRO_EXEC_INFO ExecInfo
    )
///
/// @brief Notify the scan engines about a possible malicious code execution in a Linux guest.
///
/// If the Introcore internal logic did not consider the code executions as being malicious, the scan engines
/// will be notified and they will provided a result in an asynchronous fashion.
///
/// @param[in]  Task            The Linux task that triggered the execution.
/// @param[in]  Registers       The current state of the CPU registers.
/// @param[in]  ExecInfo        Information about the execution itself.
///
{
    INTSTATUS status;
    ENG_NOTIFICATION_CODE_EXEC *pExecNotification;

    pExecNotification = NULL;

    if (NULL == Task)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == ExecInfo)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pExecNotification = HpAllocWithTag(sizeof(ENG_NOTIFICATION_CODE_EXEC), IC_TAG_ENGINE_NOT);
    if (NULL == pExecNotification)
    {
        ERROR("[ERROR] HpAllocWithTag failed!");
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _cleanup_and_exit;
    }

    IntAlertFillLixProcess(Task, &pExecNotification->ExecutionData.Process);
    IntAlertFillExecContext(0, &pExecNotification->ExecutionData.ExecContext);

    status = IntEngFillExecDetails(Registers, pExecNotification);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntEngFillExecDetails failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    memcpy(&pExecNotification->ExecutionData.StackInfo, ExecInfo, sizeof(INTRO_EXEC_INFO));

    status = IntNotifyEngines(pExecNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyEngines failed: 0x%08x\n", status);
    }

_cleanup_and_exit:

    if (!INT_SUCCESS(status))
    {
        // need to cleanup, since we won't expect the result callback for this event
        if (pExecNotification)
        {
            HpFreeAndNullWithTag(&pExecNotification, IC_TAG_ENGINE_NOT);
        }
    }

    return status;
}


INTSTATUS
IntWinEngExecSendNotification(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PIG_ARCH_REGS Registers,
    _In_ PINTRO_EXEC_INFO ExecInfo
    )
///
/// @brief Notify the scan engines about a possible malicious code execution in a Windows guest.
///
/// If the Introcore internal logic did not consider the code executions as being malicious, the scan engines
/// will be notified and they will provided a result in an asynchronous fashion.
///
/// @param[in]  Process         The Windows process that triggered the execution.
/// @param[in]  Registers       The current state of the CPU registers.
/// @param[in]  ExecInfo        Information about the execution itself.
///
{
    INTSTATUS status;
    ENG_NOTIFICATION_CODE_EXEC *pExecNotification;

    pExecNotification = NULL;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == ExecInfo)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pExecNotification = HpAllocWithTag(sizeof(ENG_NOTIFICATION_CODE_EXEC), IC_TAG_ENGINE_NOT);
    if (NULL == pExecNotification)
    {
        ERROR("[ERROR] HpAllocWithTag failed!");
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _cleanup_and_exit;
    }

    IntAlertFillWinProcess(Process, &pExecNotification->ExecutionData.Process);
    IntAlertFillExecContext(0, &pExecNotification->ExecutionData.ExecContext);

    status = IntEngFillExecDetails(Registers, pExecNotification);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntEngFillExecDetails failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    memcpy(&pExecNotification->ExecutionData.StackInfo, ExecInfo, sizeof(INTRO_EXEC_INFO));

    status = IntNotifyEngines(pExecNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyEngines failed: 0x%08x\n", status);
    }

_cleanup_and_exit:

    if (!INT_SUCCESS(status))
    {
        // need to cleanup, since we won't expect the result callback for this event
        if (pExecNotification)
        {
            HpFreeAndNullWithTag(&pExecNotification, IC_TAG_ENGINE_NOT);
        }
    }

    return status;
}


INTSTATUS
IntHandleExecCallback(
    _In_ PENG_NOTIFICATION_CODE_EXEC ExecNotification
    )
///
/// @brief Handle the code execution scan result provided by the engines.
///
/// If the introspection successfully sent a code execution notification to the engines, this callback will be
/// triggered in an asynchronous fashion. Please note that since the #ENG_NOTIFICATION_CODE_EXEC is heap allocated,
/// this callback must always be invoked (otherwise a memory leak will occur).
///
/// @param[in]  ExecNotification        The engine notification sent to the integrator from
///                                     #IntWinEngExecSendNotification or #IntLixEngExecSendNotification.
///
{
    INTSTATUS status;

    if (introGuestNotAllowed != ExecNotification->Header.RequestedAction)
    {
        goto _cleanup_and_exit;
    }

    LOG("[CODE EXECUTION] [%s] [code execution violation] Process: %s with PID:%u CR3:0x%llx "
        "and command line:%s has been exploited! Detection name: %s\n",
        ExecNotification->Header.OsType == introGuestWindows ? "WIN" : "LIX",
        ExecNotification->ExecutionData.Process.ImageName,
        ExecNotification->ExecutionData.Process.Pid,
        ExecNotification->ExecutionData.Process.Cr3,
        strlen_s(ExecNotification->ExecutionData.Process.CmdLine, 512) == 0 ?
        "N/A" : ExecNotification->ExecutionData.Process.CmdLine,
        ExecNotification->Header.DetectionName
       );

    LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");

    IntEngDumpCodeAndRegs(ExecNotification);

    status = IntEngSendExecViolation(ExecNotification);
    if (!INT_SUCCESS(status))
    {
        WARNING("[ERROR] IntEngSendExecViolation failed: 0x%08x\n", status);
    }

_cleanup_and_exit:

    if (ExecNotification)
    {
        HpFreeAndNullWithTag(&ExecNotification, IC_TAG_ENGINE_NOT);
    }

    return INT_STATUS_SUCCESS;
}
