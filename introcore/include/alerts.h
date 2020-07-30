/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ALERTS_H_
#define _ALERTS_H_

#include "exceptions.h"
#include "intronet.h"

///
/// @brief  Holds all the alert types.
///
typedef union _GENERIC_ALERT
{
    EVENT_EPT_VIOLATION                 Ept;
    EVENT_MSR_VIOLATION                 Msr;
    EVENT_CR_VIOLATION                  Cr;
    EVENT_XCR_VIOLATION                 Xcr;
    EVENT_DTR_VIOLATION                 Dtr;
    EVENT_MEMCOPY_VIOLATION             Injection;
    EVENT_TRANSLATION_VIOLATION         Translation;
    EVENT_INTEGRITY_VIOLATION           Integrity;
    EVENT_INTROSPECTION_MESSAGE         Message;
    EVENT_PROCESS_EVENT                 Process;
    EVENT_MODULE_EVENT                  Module;
    EVENT_CRASH_EVENT                   Crash;
    EVENT_EXCEPTION_EVENT               Exception;
    EVENT_AGENT_EVENT                   Agent;
    EVENT_CONNECTION_EVENT              Connection;
    EVENT_PROCESS_CREATION_VIOLATION    ProcessCreation;
    EVENT_MODULE_LOAD_VIOLATION         ModuleLoad;
    EVENT_ENGINES_DETECTION_VIOLATION   EngineDetection;
} GENERIC_ALERT;

extern GENERIC_ALERT gAlert;

INTSTATUS
IntAlertFillExecContext(
    _In_ QWORD Cr3,
    _Out_ INTRO_EXEC_CONTEXT *ExecContext
    );

INTSTATUS
IntAlertFillCodeBlocks(
    _In_ QWORD Rip,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Execute,
    _Out_ INTRO_CODEBLOCKS *CodeBlocks
    );

void
IntAlertFillVersionInfo(
    _Out_ INTRO_VIOLATION_HEADER *Header
    );

QWORD
IntAlertCoreGetFlags(
    _In_ QWORD ProtectionFlag,
    _In_ INTRO_ACTION_REASON Reason
    );

QWORD
IntAlertProcGetFlags(
    _In_ QWORD ProtectionFlag,
    _In_opt_ const void *Process,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ QWORD AdditionalFlags
    );

void
IntAlertFillCpuContext(
    _In_ BOOLEAN CopyInstruction,
    _Out_ INTRO_CPUCTX *CpuContext
    );

void
IntAlertFillDriverObject(
    _In_ const WIN_DRIVER_OBJECT *DriverObject,
    _Out_ INTRO_DRVOBJ *EventDrvObj
    );

void
IntAlertFillWinKmModule(
    _In_opt_ const KERNEL_DRIVER *Driver,
    _Out_ INTRO_MODULE *EventModule
    );

void
IntAlertFillWinUmModule(
    _In_opt_ const WIN_PROCESS_MODULE *Module,
    _Out_ INTRO_MODULE *EventModule
    );

void
IntAlertFillWinProcess(
    _In_ const WIN_PROCESS_OBJECT *Process,
    _Out_ INTRO_PROCESS *EventProcess
    );

void
IntAlertFillWinProcessByCr3(
    _In_ QWORD ProcessCr3,
    _Out_ INTRO_PROCESS *EventProcess
    );

void
IntAlertFillWinProcessCurrent(
    _Out_ INTRO_PROCESS *EventProcess
    );

void
IntAlertEptFillFromUmOriginator(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    );

void
IntAlertEptFillFromKmOriginator(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    );

void
IntAlertEptFillFromVictimZone(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    );

void
IntAlertMsrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_MSR_VIOLATION *MsrViolation
    );

void
IntAlertDtrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_DTR_VIOLATION *DtrViolation
    );

void
IntAlertCrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_CR_VIOLATION *CrViolation
    );

void
IntAlertFillLixKmModule(
    _In_ const KERNEL_DRIVER *Driver,
    _Out_ INTRO_MODULE *EventModule
    );

void
IntAlertFillLixProcess(
    _In_ const LIX_TASK_OBJECT *Task,
    _Out_ INTRO_PROCESS *EventProcess
    );

void
IntAlertFillLixCurrentProcess(
    _Out_ INTRO_PROCESS *EventProcess
    );

void
IntAlertFillWriteInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ INTRO_WRITE_INFO *WriteInfo
    );

void
IntAlertFillConnection(
    _In_ const INTRONET_ENDPOINT *Connection,
    _Out_ EVENT_CONNECTION_EVENT *Event
    );

INTSTATUS
IntAlertFillDpiExtraInfo(
    _In_ DPI_EXTRA_INFO *CollectedExtraInfo,
    _In_ INTRO_PC_VIOLATION_TYPE PcType,
    _In_ WIN_PROCESS_OBJECT *VictimProcess,
    _Out_ INTRO_DPI_EXTRA_INFO *ExtraInfo

    );

#endif // _ALERTS_H_
