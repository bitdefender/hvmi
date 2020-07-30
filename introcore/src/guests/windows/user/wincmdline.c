/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wincmdline.h"
#include "winprocesshp.h"
#include "alerts.h"

///
/// @file wincmdline.c
///
/// @brief This file handles command line scanning.
///
/// Introcore may request the AV engines to scan the command line of certain processes (for example, Powershell).
/// Unfortunately, the scheduling of a command line scan could bring a considerable performance penalty so the scan
/// will be carried out in an asynchronous fashion. If the scan scheduling was successful, the integrator must invoke
/// the registered callback (#PFUNC_IntEventEnginesResultCallback) in order to provide the scan result. For now, if a
/// malicious command line is being used, the process will not be blocked (since the scan is asynchronous, blocking it
/// would require the injection of an agent).
///


INTSTATUS
IntWinInspectCommandLine(
    _In_ PWIN_PROCESS_OBJECT Process
    )
///
/// @brief Send a command line scan request to the scan engines.
///
/// If this function succeeds, the integrator must call the #PFUNC_IntEventEnginesResultCallback,
/// otherwise a memory leak will occur.
///
/// @param[in]  Process     The process structure (it contains the command line and other fields).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *pParent;
    ENG_NOTIFICATION_CMD_LINE *pNotification;

    pNotification = HpAllocWithTag(sizeof(ENG_NOTIFICATION_CMD_LINE), IC_TAG_ENGINE_NOT);
    if (NULL == pNotification)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pNotification->Header.Type = introEngineNotificationCmdLine;
    pNotification->Header.OsType = introGuestWindows;

    // It could be NULL (in case the parent process no longer exists).
    pParent = IntWinProcFindObjectByEprocess(Process->ParentEprocess);

    IntAlertFillWinProcess(Process, &pNotification->Child);
    IntAlertFillWinProcess(pParent, &pNotification->Parent);

    pNotification->CmdLineSize = Process->CommandLineSize;
    pNotification->CmdLine = HpAllocWithTag(pNotification->CmdLineSize, IC_TAG_CMD_LINE);
    if (NULL == pNotification->CmdLine)
    {
        HpFreeAndNullWithTag(&pNotification, IC_TAG_ENGINE_NOT);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(pNotification->CmdLine, Process->CommandLine, Process->CommandLineSize);

    LOG("[CMDLINE] Asking the engines to scan process:%s with PID:%u command line:%s - with size:%u\n",
        pNotification->Child.ImageName, pNotification->Child.Pid,
        pNotification->CmdLine, pNotification->CmdLineSize
       );

    status = IntNotifyEngines(pNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyEngines failed: 0x%x\n", status);
    }

    // Something went wrong. We are going to free the memory.
    if (!INT_SUCCESS(status))
    {
        if (pNotification)
        {
            if (pNotification->CmdLine)
            {
                HpFreeAndNullWithTag(&pNotification->CmdLine, IC_TAG_CMD_LINE);
            }

            HpFreeAndNullWithTag(&pNotification, IC_TAG_ENGINE_NOT);
        }
    }

    return status;
}


static INTSTATUS
IntWinSendCmdLineViolation(
    _In_ PENG_NOTIFICATION_CMD_LINE EngineNotification
    )
///
/// @brief Send a command line violation event.
///
/// @param[in]  EngineNotification     The engine notification containing the scan result.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;
    EVENT_ENGINES_DETECTION_VIOLATION *pEvent;
    INTRO_ACTION_REASON reason;

    pEvent = &gAlert.EngineDetection;
    memzero(pEvent, sizeof(*pEvent));

    reason = introReasonAllowedFeedback;

    pEvent->Header.Action = EngineNotification->Header.RequestedAction;
    pEvent->Header.Reason = reason;

    pEvent->Header.Flags = IntAlertProcGetFlags(0, NULL, reason, ALERT_FLAG_FROM_ENGINES);
    pEvent->Header.Flags |= ALERT_FLAG_NOT_RING0;
    pEvent->Header.MitreID = idScripting;

    if (0 == strcasecmp("powershell.exe", EngineNotification->Child.ImageName))
    {
        pEvent->Header.MitreID = idPowerShell;
    }

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
IntWinHandleCmdLineCallback(
    _In_ PENG_NOTIFICATION_CMD_LINE EngineNotification
    )
///
/// @brief Handle a command line scan response.
///
/// @param[in]  EngineNotification     The engine notification containing the scan result.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;

    if (introGuestNotAllowed != EngineNotification->Header.RequestedAction)
    {
        LOG("[CMDLINE] process:%s with PID:%u used a clean command line\n",
            EngineNotification->Child.ImageName, EngineNotification->Child.Pid);
        goto free_memory;
    }

    LOG("[CMDLINE] [command line violation] process:%s with PID:%u, CR3:0x%llx and command line:%s created "
        "process:%s with PID:%u, CR3:0x%llx using the malicious command line:%s\n",
        EngineNotification->Parent.ImageName,
        EngineNotification->Parent.Pid,
        EngineNotification->Parent.Cr3,
        EngineNotification->Parent.CmdLine,
        EngineNotification->Child.ImageName,
        EngineNotification->Child.Pid,
        EngineNotification->Child.Cr3,
        EngineNotification->Child.CmdLine
       );
    LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ MALWARE ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");

    status = IntWinSendCmdLineViolation(EngineNotification);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinPsSendCmdLineViolation failed with status: 0x%08x\n", status);
    }

free_memory:
    if (NULL != EngineNotification->CmdLine)
    {
        HpFreeAndNullWithTag(&EngineNotification->CmdLine, IC_TAG_CMD_LINE);
    }

    HpFreeAndNullWithTag(&EngineNotification, IC_TAG_ENGINE_NOT);

    return INT_STATUS_SUCCESS;
}
