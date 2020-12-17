/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixcmdline.h"
#include "alerts.h"

///
/// @file lixcmdline.c
///
/// @brief This file handles command line scanning.
///
/// Introcore may request the AV engines to scan the command line of certain processes.
/// Unfortunately, the scheduling of a command line scan could bring a considerable performance penalty so the scan
/// will be carried out in an asynchronous fashion. If the scan scheduling was successful, the integrator must invoke
/// the registered callback (#PFUNC_IntEventEnginesResultCallback) in order to provide the scan result. For now, if a
/// malicious command line is being used, the process will not be blocked (since the scan is asynchronous, blocking it
/// would require the injection of an agent).
///


static INTSTATUS
IntLixCmdLineSendViolationEvent(
    _In_ ENG_NOTIFICATION_CMD_LINE *EngineNotification
    )
///
/// @brief Send a command line violation event.
///
/// @param[in]  EngineNotification      The engine notification containing the scan result.
///
/// @retval #INT_STATUS_SUCCESS         On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_ENGINES_DETECTION_VIOLATION *pEvent = &gAlert.EngineDetection;
    INTRO_ACTION_REASON reason = introReasonAllowedFeedback;
    LIX_TASK_OBJECT *pTask = IntLixTaskFindByCr3(EngineNotification->Child.Cr3);

    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = EngineNotification->Header.RequestedAction;
    pEvent->Header.Reason = reason;

    pEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_SCAN_CMD_LINE, pTask, reason, ALERT_FLAG_FROM_ENGINES);
    pEvent->Header.Flags |= ALERT_FLAG_NOT_RING0;
    pEvent->Header.MitreID = idScripting;

    IntAlertFillVersionInfo(&pEvent->Header);

    pEvent->Type = introEngineNotificationCmdLine;
    memcpy(&pEvent->Header.CurrentProcess, &EngineNotification->Parent, sizeof(INTRO_PROCESS));
    memcpy(&pEvent->CmdLineViolation.Originator, &EngineNotification->Parent, sizeof(INTRO_PROCESS));
    memcpy(&pEvent->CmdLineViolation.Victim, &EngineNotification->Child, sizeof(INTRO_PROCESS));

    memcpy(&pEvent->DetectionName[0], &EngineNotification->Header.DetectionName[0], ALERT_MAX_DETECTION_NAME - 1);
    memcpy(&pEvent->EnginesVersion[0], &EngineNotification->Header.EnginesVersion[0], ALERT_MAX_ENGINES_VERSION - 1);
    pEvent->DetectionName[ALERT_MAX_DETECTION_NAME - 1] = 0;

    status = IntNotifyIntroEvent(introEventEnginesDetectionViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixCmdLineInspect(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Send a command line scan request to the scan engines.
///
/// If this function succeeds, the integrator must call the #PFUNC_IntEventEnginesResultCallback,
/// otherwise a memory leak will occur.
///
/// @param[in]  Task                The process structure (it contains the command line and other fields).
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If the allocation fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    ENG_NOTIFICATION_CMD_LINE *pNotification = NULL;
    LIX_TASK_OBJECT *pParent = NULL;

    pNotification = HpAllocWithTag(sizeof(ENG_NOTIFICATION_CMD_LINE), IC_TAG_ENGINE_NOT);
    if (pNotification == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pParent = IntLixTaskFindByGva(Task->Parent);
    IntAlertFillLixProcess(Task, &pNotification->Child);
    IntAlertFillLixProcess(pParent, &pNotification->Parent);

    pNotification->Header.Type = introEngineNotificationCmdLine;
    pNotification->Header.OsType = introGuestLinux;

    pNotification->CmdLineSize = Task->CmdLineLength;
    pNotification->CmdLine = HpAllocWithTag(pNotification->CmdLineSize, IC_TAG_CMD_LINE);
    if (NULL == pNotification->CmdLine)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _exit;
    }

    memcpy(pNotification->CmdLine, Task->CmdLine, Task->CmdLineLength);

    LOG("[LIX-CMDLINE] Scan request for task '%s' with PID %u using command line '%s' (%u)\n",
        pNotification->Child.ImageName, pNotification->Child.Pid, pNotification->CmdLine, pNotification->CmdLineSize);

    status = IntNotifyEngines(pNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyEngines failed with status: 0x%08x\n", status);
        goto _exit;
    }

    return INT_STATUS_SUCCESS;

_exit:
    if (pNotification != NULL)
    {
        if (pNotification->CmdLine)
        {
            HpFreeAndNullWithTag(&pNotification->CmdLine, IC_TAG_CMD_LINE);
        }

        HpFreeAndNullWithTag(&pNotification, IC_TAG_ENGINE_NOT);
    }

    return status;
}


INTSTATUS
IntLixHandleCmdLineCallback(
    _In_ ENG_NOTIFICATION_CMD_LINE *EngineNotification
    )
///
/// @brief Send a command line violation event.
///
/// @param[in]  EngineNotification      The engine notification containing the scan result.
///
/// @retval #INT_STATUS_SUCCESS         On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (introGuestNotAllowed != EngineNotification->Header.RequestedAction)
    {
        TRACE("[LIX-CMDLINE] Task '%s' with PID %u used a clean command line...\n",
            EngineNotification->Child.ImageName, EngineNotification->Child.Pid);
        goto _exit;
    }

    LOG("[LIX-CMDLINE] Parent task '%s' (%u) CR3 = 0x%016llx with command line '%s'\n",
        EngineNotification->Parent.ImageName, EngineNotification->Parent.Pid, EngineNotification->Parent.Cr3,
        EngineNotification->Parent.CmdLine);
    LOG("[LIX-CMDLINE] Child task '%s' (%u) CR3 = 0x%016llx with command line '%s'\n",
        EngineNotification->Child.ImageName, EngineNotification->Child.Pid, EngineNotification->Child.Cr3,
        EngineNotification->Child.CmdLine);
    LOG("[LIX-CMDLINE] Detection name: '%s'\n", EngineNotification->Header.DetectionName);

    LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");

    status = IntLixCmdLineSendViolationEvent(EngineNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCmdLineSendViolationEvent failed with status: 0x%08x\n", status);
    }

_exit:
    if (NULL != EngineNotification->CmdLine)
    {
        HpFreeAndNullWithTag(&EngineNotification->CmdLine, IC_TAG_CMD_LINE);
    }

    HpFreeAndNullWithTag(&EngineNotification, IC_TAG_ENGINE_NOT);

    return INT_STATUS_SUCCESS;
}

