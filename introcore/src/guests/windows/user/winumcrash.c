/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */

#include "winumcrash.h"
#include "alerts.h"
#include "guests.h"
#include "shellcode.h"
#include "winprocesshp.h"
#include "winthread.h"


// These are defined by the Windows SDK headers in minwinbase.h
// Can also be found on here: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
#define STILL_ACTIVE                        0x00000103L
#define EXCEPTION_ACCESS_VIOLATION          0xC0000005L
#define EXCEPTION_DATATYPE_MISALIGNMENT     0x80000002L
#define EXCEPTION_BREAKPOINT                0x80000003L
#define EXCEPTION_SINGLE_STEP               0x80000004L
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     0xC000008CL
#define EXCEPTION_FLT_DENORMAL_OPERAND      0xC000008DL
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        0xC000008EL
#define EXCEPTION_FLT_INEXACT_RESULT        0xC000008FL
#define EXCEPTION_FLT_INVALID_OPERATION     0xC0000090L
#define EXCEPTION_FLT_OVERFLOW              0xC0000091L
#define EXCEPTION_FLT_STACK_CHECK           0xC0000092L
#define EXCEPTION_FLT_UNDERFLOW             0xC0000093L
#define EXCEPTION_INT_DIVIDE_BY_ZERO        0xC0000094L
#define EXCEPTION_INT_OVERFLOW              0xC0000095L
#define EXCEPTION_PRIV_INSTRUCTION          0xC0000096L
#define EXCEPTION_IN_PAGE_ERROR             0xC0000006L
#define EXCEPTION_ILLEGAL_INSTRUCTION       0xC000001DL
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  0xC0000025L
#define EXCEPTION_STACK_OVERFLOW            0xC00000FDL
#define EXCEPTION_INVALID_DISPOSITION       0xC0000026L
#define EXCEPTION_GUARD_PAGE                0x80000001L
#define EXCEPTION_INVALID_HANDLE            0xC0000008L
#define EXCEPTION_POSSIBLE_DEADLOCK         0xC0000194L
#define CONTROL_C_EXIT                      0xC000013AL


// These values are used internally by the Windows exception dispatching mechanism
#define KI_EXCEPTION_INTERNAL                   0x10000000
/// @brief      General protection fault
#define KI_EXCEPTION_GP_FAULT                   ((INTSTATUS)(KI_EXCEPTION_INTERNAL | 0x01))
/// @brief      Invalid opcode exceptions
#define KI_EXCEPTION_INVALID_OP                 ((INTSTATUS)(KI_EXCEPTION_INTERNAL | 0x02))
/// @brief      Divide error
#define KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO     ((INTSTATUS)(KI_EXCEPTION_INTERNAL | 0x03))
/// @brief      Page fault
#define KI_EXCEPTION_ACCESS_VIOLATION           ((INTSTATUS)(KI_EXCEPTION_INTERNAL | 0x04))

#define KERNEL_MODE             0   ///< The event was triggered inside the kernel space
#define USER_MODE               1   ///< The event was triggered inside the user space

// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx
#define FLG_CONTINUABLE         0
#define FLG_NON_CONTINUABLE     1

///
/// @brief      The type of event that caused the access violation
///
/// The first element of the ExceptionInformation array of an exception record indicates the type of operation that
/// caused the access violation.
///
typedef enum
{
    PARAM1_READ  = 0,   ///< Attempt to read inaccessible data
    PARAM1_WRITE = 1,   ///< Attempt to write inaccessible data
    PARAM1_DEP   = 8,   ///< A user-mode data execution prevention (DEP) violation
} ACCESS_VIOLATION_EVENT;

///
/// @brief      Checks if a fault is an access violation caused by DEP
///
/// @param[in]  Er  The exception record structure. Either a #EXCEPTION_RECORD32 or a #EXCEPTION_RECORD64
///
/// @returns    True if this is an access violation caused by DEP, False if it is not
///
#define IS_DEP_FAULT(Er)        ((EXCEPTION_ACCESS_VIOLATION == (Er).ExceptionCode) && \
                                 !IS_KERNEL_POINTER_WIN(gGuest.Guest64, (Er).ExceptionAddress) && \
                                 (PARAM1_DEP == (Er).ExceptionInformation[0]))

#define CODE_SEG_UM_32 0x20 ///< 32-bit user mode code selector
#define CODE_SEG_UM_64 0x30 ///< 64-bit user mode code selector


static __forceinline
_Success_(return != FALSE) BOOLEAN
IntWinPreProcessException(
    _In_ DWORD ExceptionCode,
    _Out_ DWORD *Status
    )
///
/// @brief      Translates an internal kernel exception code to an exception status known by used mode applications,
///             which is usually a NTSTATUS value
///
/// Some of the conversions done here are based on what the KiPreprocessFault Windows kernel function is doing.
///
/// @param[in]  ExceptionCode   The kernel exception code to be converted. This is the code extracted from the
///                             exception record read from the kernel
/// @param[out] Status          On success, the exception status
///
/// @retval     True if ExceptionCode was known
/// @retval     False if it was not known and no conversion was possible
///
{
    switch (ExceptionCode)
    {
    case KI_EXCEPTION_INVALID_OP:
        *Status = EXCEPTION_ILLEGAL_INSTRUCTION;
        return TRUE;

    case KI_EXCEPTION_INTEGER_DIVIDE_BY_ZERO:
        *Status = EXCEPTION_INT_DIVIDE_BY_ZERO;
        return TRUE;

    case KI_EXCEPTION_ACCESS_VIOLATION:
    // it seems that KiPreprocessFault treats KI_EXCEPTION_GP_FAULT the same as EXCEPTION_ACCESS_VIOLATION
    case KI_EXCEPTION_GP_FAULT:
        *Status = EXCEPTION_ACCESS_VIOLATION;
        return TRUE;

    // nothing to change for these
    case STILL_ACTIVE:
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_BREAKPOINT:
    case EXCEPTION_SINGLE_STEP:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_FLT_DENORMAL_OPERAND:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_INEXACT_RESULT:
    case EXCEPTION_FLT_INVALID_OPERATION:
    case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_UNDERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_INVALID_DISPOSITION:
    case EXCEPTION_GUARD_PAGE:
    case EXCEPTION_INVALID_HANDLE:
    case EXCEPTION_POSSIBLE_DEADLOCK:
    case CONTROL_C_EXIT:
        *Status = ExceptionCode;
        return TRUE;

    default:
        return FALSE;
    }
}


static void
IntWinFillRegsFromExceptionInfo(
    _In_ void const *TrapFrame,
    _In_opt_ KEXCEPTION_FRAME64 const *ExFrame,
    _Out_ IG_ARCH_REGS *Regs
    )
///
/// @brief      Reads the guest registers available inside the guest exception information structures
///
/// @param[in]  TrapFrame   The guest trap frame. #KTRAP_FRAME64 for 64-bit kernels, #KTRAP_FRAME32 for 32-bit
///                         kernels
/// @param[in]  ExFrame     The exception frame structure. Needed only for 64-bit kernels.
/// @param[out] Regs        The reigster values
///
{
    if (gGuest.Guest64)
    {
        KTRAP_FRAME64 const *tf = TrapFrame;

        Regs->Rax = tf->Rax;
        Regs->Rcx = tf->Rcx;
        Regs->Rdx = tf->Rdx;
        Regs->Rbx = tf->Rbx;
        Regs->Rsp = tf->Rsp;
        Regs->Rbp = tf->Rbp;
        Regs->Rsi = tf->Rsi;
        Regs->Rdi = tf->Rdi;
        Regs->R8 = tf->R8;
        Regs->R9 = tf->R9;
        Regs->R10 = tf->R10;
        Regs->R11 = tf->R11;

        if (ExFrame)
        {
            Regs->R12 = ExFrame->R12;
            Regs->R13 = ExFrame->R13;
            Regs->R14 = ExFrame->R14;
            Regs->R15 = ExFrame->R15;
        }

        Regs->Flags = tf->EFlags;
    }
    else
    {
        KTRAP_FRAME32 const *tf = TrapFrame;

        Regs->Rax = tf->Eax;
        Regs->Rcx = tf->Ecx;
        Regs->Rdx = tf->Edx;
        Regs->Rbx = tf->Ebx;
        Regs->Rsp = tf->HardwareEsp;
        Regs->Rbp = tf->Ebp;
        Regs->Rsi = tf->Esi;
        Regs->Rdi = tf->Edi;
        Regs->Flags = tf->EFlags;
    }
}


static INTSTATUS
IntWinCrashHandleDepViolation(
    _In_ void const *ExceptionRecord,
    _In_ QWORD ExceptionFrameGva,
    _In_ QWORD TrapFrameGva
    )
///
/// @brief      Handles a crash generated by a DEP violation
///
/// For processes that opt-out of DEP, the stack and heap may be created as executable from the start. In those cases,
/// if they are protected with #PROC_OPT_PROT_EXPLOIT, introcore enforces DEP for them using
/// #IntWinProcEnforceProcessDep. In those cases, even if introcore hooks the stack and the heap against executions,
/// a page fault will be triggered in guest, and that will be delivered before the EPT violation will be triggered.
/// We still want to send an alert in those cases, so we intercept it and convert it to an #introEventEptViolation.
/// Note that in this cases the action taken by introcore is not relevant, as the action will be blocked directly
/// by the OS page fault handler, so the action set in the event will always be #introGuestNotAllowed. We consult
/// the exceptions mechanism, but if an exception matches we will not send an alert, but the process will probably
/// be killed by the OS.
/// The conversion is slightly more complicated than it sounds, as we are in the context of the kernel, trying to
/// reconstruct the context of the user mode application at the time it triggered the DEP violation. Some information
/// may no longer be available, or it may have changed.
///
/// @param[in]  ExceptionRecord     The exception record obtained from the guest. Pointer to a #EXCEPTION_RECORD64
///                                 structure for 64-bit kernels, and a #EXCEPTION_RECORD32 structure for 32-bit
///                                 kernels
/// @param[in]  ExceptionFrameGva   The guest virtual address at which the exception frame starts. Used only for
///                                 64-bit kernels
/// @param[in]  TrapFrameGva        The guest virtual address at which the _KTRAP_FRAME structure is located
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    PWIN_PROCESS_OBJECT pProc;
    IG_ARCH_REGS regs = { 0 };
    QWORD gpa = 0;
    DWORD csType;
    EVENT_EPT_VIOLATION *pEvent;
    QWORD tibBase = 0;
    QWORD stackBase = 0;
    QWORD stackLimit = 0;
    BOOLEAN bRspOut = FALSE;
    BOOLEAN bIsStack = FALSE;
    EXCEPTION_UM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;
    QWORD scflags = 0;

    pProc = IntWinProcFindObjectByCr3(gVcpu->Regs.Cr3);
    if (NULL == pProc || !pProc->Protected || !pProc->ProtExploits || !pProc->EnforcedDep)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gGuest.Guest64)
    {
        EXCEPTION_RECORD64 const *pEr = ExceptionRecord;
        KTRAP_FRAME64 tf = { 0 };
        KEXCEPTION_FRAME64 ef = { 0 };

        // Read the trap and the exception frames in order to reconstruct the process state at the moment of the #PF
        status = IntKernVirtMemRead(TrapFrameGva, sizeof(tf), &tf, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", TrapFrameGva, status);
            return status;
        }

        status = IntKernVirtMemRead(ExceptionFrameGva, sizeof(ef), &ef, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", ExceptionFrameGva, status);
            return status;
        }

        // Reconstruct the context
        IntWinFillRegsFromExceptionInfo(&tf, &ef, &regs);
        regs.Rip = pEr->ExceptionAddress;
        regs.Cr3 = gVcpu->Regs.Cr3;

        switch (tf.SegCs & ~0x7)
        {
        case CODE_SEG_UM_32:
            csType  = IG_CS_TYPE_32B;
            break;

        case CODE_SEG_UM_64:
            csType = IG_CS_TYPE_64B;
            break;

        default:
            WARNING("[WARNING] Unrecognized CS value: 0x%08x\n", tf.SegCs);
            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }
    else
    {
        EXCEPTION_RECORD32 const *pEr = ExceptionRecord;
        KTRAP_FRAME32 tf = { 0 };

        // Read the trap frame in order to reconstruct the process state at the moment of the #PF
        status = IntKernVirtMemRead(TrapFrameGva, sizeof(tf), &tf, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", TrapFrameGva, status);
            return status;
        }

        // The exception frame is not needed on 32-bit guests

        // Reconstruct the context
        IntWinFillRegsFromExceptionInfo(&tf, NULL, &regs);
        regs.Rip = pEr->ExceptionAddress;
        regs.Cr3 = gVcpu->Regs.Cr3;

        csType = IG_CS_TYPE_32B;
    }

    status = IntTranslateVirtualAddress(regs.Rip, gVcpu->Regs.Cr3, &gpa);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntTranslateVirtualAddress failed for 0x%016llx and Cr3 0x%016llx: 0x%08x\n",
                regs.Rip, gVcpu->Regs.Cr3, status);
        // I think we can safely go on with sending the alert
        // NOTE: We won't send the alert if we couldn't translate the RIP page, because we won't be able to run the
        // shellcode emulator on it.
        return INT_STATUS_SUCCESS;
    }

    status = IntWinThrGetCurrentTib(IG_CS_RING_0, csType, &tibBase);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinThrGetCurrentTib failed: 0x%08x\n", status);
        // Go on with stack base/limit set to 0
    }
    else
    {
        status = IntWinThrGetUmStackBaseAndLimitFromTib(tibBase, csType, regs.Cr3, &stackBase, &stackLimit);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinThrGetUmStackBaseAndLimitFromTib failed: 0x%08x\n", status);
            // Go on with stack base/limit set to 0
        }
        else
        {
            bRspOut = ((regs.Rsp < stackLimit - 0x3000) || (regs.Rsp >= stackBase));
            bIsStack = (regs.Rip >= stackLimit) && (regs.Rip < stackBase);
        }
    }

    // Call the shellcode emulator on the affected page. Note that we have to provide the CS type ourselves, because
    // right now, we are in kernel context, and on a 64 bit machine, this will result in a 64b CS type, even if the
    // crashing application was running in compatibility (32b) mode.
    status = IntShcIsSuspiciousCode(regs.Rip, gpa, csType, &regs, &scflags);
    if (!INT_SUCCESS(status))
    {
        scflags = 0;
    }

    if (!(bRspOut || bIsStack || (0 != scflags)))
    {
        // No detection was triggered by our heuristics, there's no need to send an alert. This avoids multiple FPs
        // triggered in various places due to faulty code which randomly crashes.
        return INT_STATUS_SUCCESS;
    }

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    status = IntExceptUserGetExecOriginator(pProc, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _skip_log;
    }

    originator.Rip = regs.Rip;
    originator.SourceVA = regs.Rip;

    status = IntExceptGetVictimEpt(pProc, gpa, regs.Rip, introObjectTypeUmGenericNxZone,
                                   ZONE_EXECUTE | ZONE_DEP_EXECUTION, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _skip_log;
    }

    IntExceptUserLogInformation(&victim, &originator, introGuestNotAllowed, introReasonNoException);

_skip_log:
    LOG("[DEP] [CPU %d] EXPLOIT detected! Execution attempted at 0x%016llx!\n", gVcpu->Index, regs.Rip);
    LOG("[DEP] Current address: 0x%016llx, current stack: 0x%016llx, known stack: 0x%016llx/0x%016llx, "
        "TIB: 0x%016llx\n", regs.Rip, regs.Rsp, stackBase, stackLimit, tibBase);
    LOG("[DEP] RSP out: %d; Is stack: %d; ScFlags: 0x%llx\n", bRspOut, bIsStack, scflags);

    IntDumpCodeAndRegs(regs.Rip, gpa, &regs);

    pEvent = &gAlert.Ept;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = introGuestNotAllowed;
    pEvent->Header.Reason = introReasonNoException;
    pEvent->Header.MitreID = idExploitClientExec;

    pEvent->Header.Flags = IntAlertProcGetFlags(0, NULL, introReasonUnknown, 0);

    if (pProc->SystemProcess)
    {
        pEvent->Header.Flags |= ALERT_FLAG_SYSPROC;
    }

    pEvent->Header.Flags |= ALERT_FLAG_DEP_VIOLATION;

    pEvent->Victim.Type = introObjectTypeUmGenericNxZone;
    pEvent->Violation = IG_EPT_HOOK_EXECUTE;

    pEvent->HookStartPhysical = gpa & PHYS_PAGE_MASK;
    pEvent->HookStartVirtual = regs.Rip & PAGE_MASK;
    pEvent->VirtualPage = regs.Rip & PAGE_MASK;
    pEvent->Offset = regs.Rip & 0xFFF;

    pEvent->Header.CpuContext.Valid = TRUE;
    pEvent->Header.CpuContext.Rip = regs.Rip;
    pEvent->Header.CpuContext.Cr3 = regs.Cr3;
    pEvent->Header.CpuContext.Cpu = gVcpu->Index;

    IntAlertFillWinProcess(pProc, &pEvent->Header.CurrentProcess);

    // For execute-alerts, original & new value have different meaning, since an actual write is not being made.
    pEvent->ExecInfo.Rsp = regs.Rsp;
    pEvent->ExecInfo.StackBase = stackBase;
    pEvent->ExecInfo.StackLimit = stackLimit;
    pEvent->ExecInfo.Length = 0;

    pEvent->CodeBlocks.Valid = FALSE;

    pEvent->ExecContext.CsType = csType;
    memcpy(&pEvent->ExecContext.Registers, &regs, sizeof(pEvent->ExecContext.Registers));
    status = IntVirtMemRead(regs.Rip & PAGE_MASK, sizeof(pEvent->ExecContext.RipCode),
                            regs.Cr3, &pEvent->ExecContext.RipCode, NULL);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntVirtMemRead failed for 0x%016llx: 0x%08x\n", regs.Rip & PAGE_MASK, status);
    }

    IntAlertFillVersionInfo(&pEvent->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinSetUmExceptionEvent(
    _In_ void const *ExceptionRecord
    )
///
/// @brief      Sets the last exception triggered by a process
///
/// This is used when the #INTRO_OPT_EVENT_PROCESS_CRASH option is set. We won't send an event every time a process
/// triggers an exception, as some processes may trigger a lot of exceptions and that will cause a performance impact.
/// Instead, we save the last one, the assumption being that if the process crashes, the last exception may have
/// something to do with it.
///
/// @param[in]  ExceptionRecord     The exception record structure. Points to a #EXCEPTION_RECORD64 structure on
///                                 64-bit guests, and to a #EXCEPTION_RECORD32 structure on 32-bit guests
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if ExceptionRecord is NULL
/// @retval     #INT_STATUS_NOT_FOUND is no process is found
///
{
    PWIN_PROCESS_OBJECT pProc;

    if (NULL == ExceptionRecord)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pProc = IntWinGetCurrentProcess();
    if (NULL == pProc)
    {
        ERROR("[ERROR] Can not find process. Current CR3 = 0x%016llx\n", gVcpu->Regs.Cr3);
        return INT_STATUS_NOT_FOUND;
    }

    if (gGuest.Guest64)
    {
        EXCEPTION_RECORD64 const *pRecord = ExceptionRecord;

        pProc->LastException = pRecord->ExceptionCode;
        pProc->LastExceptionRip = pRecord->ExceptionAddress;
        pProc->LastExceptionContinuable = FLG_NON_CONTINUABLE != pRecord->ExceptionFlags;

        if (pProc->Protected)
        {
            LOG("[UMEXCEPTION] Code: 0x%08x at RIP 0x%016llx inside process `%s` (Pid %d, Cr3 0x%016llx). "
                "Continuable: %d\n", pRecord->ExceptionCode, pRecord->ExceptionAddress, pProc->Name, pProc->Pid,
                pProc->Cr3, pProc->LastExceptionContinuable);
        }
    }
    else
    {
        EXCEPTION_RECORD32 const *pRecord = ExceptionRecord;

        pProc->LastException = pRecord->ExceptionCode;
        pProc->LastExceptionRip = pRecord->ExceptionAddress;
        pProc->LastExceptionContinuable = FLG_NON_CONTINUABLE != pRecord->ExceptionFlags;

        if (pProc->Protected)
        {
            LOG("[UMEXCEPTION] Code: 0x%08x at RIP 0x%08x inside process `%s` (Pid %d, Cr3 0x%016llx). "
                "Continuable: %d\n", (DWORD)pRecord->ExceptionCode, pRecord->ExceptionAddress, pProc->Name, pProc->Pid,
                pProc->Cr3, pProc->LastExceptionContinuable);
        }
    }
    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinHandleException(
    _In_ void *Detour
    )
///
/// @brief      Handles a hardware exception triggered inside the guest
/// @ingroup    group_detours
///
/// This is the detour handler for the guest KiDispatchException function:
/// @code
///     void
///     KiDispatchException(
///         _In_ PEXCEPTION_RECORD ExceptionRecord,
///         _In_opt_ PKEXCEPTION_FRAME ExceptionFrame,
///         _In_ PKTRAP_FRAME TrapFrame,
///         _In_ KPROCESSOR_MODE PreviousMode,
///         _In_ BOOLEAN FirstChance
///         );
/// @endcode
///
/// This should catch any exception that originated in user mode.
/// On windows 10, if a process has crashed it will have the Crashed bit set inside _EPROCESSS.Flags3
/// If __fastfail() was used, the error code will be the NTSTATUS value associated with the fast fail code used,
/// and the Crashed bit will be set. See https://docs.microsoft.com/en-us/cpp/intrinsics/fastfail
/// Some error codes are NTSTATUS values, some will be converted to a NTSTATUS value before execution is handed back
/// to the guest.
/// Some exceptions generated by higher-level languages will end up in KiDispatchException, but the Crashed bit will
/// not be set.
/// If the exception was generated by a DEP violation, an alert may be sent. See #IntWinCrashHandleDepViolation.
/// Exceptions that originated inside the kernel (PreviousMode is #KERNEL_MODE) are ignored. The divide error generated
/// by patch guard when Windows boots is also ignored.
///
/// @param[in]  Detour  The detour handle
///
{
    INTSTATUS status;
    PIG_ARCH_REGS pRegs;
    QWORD prevMode;
    QWORD erGva;
    QWORD efGva;
    QWORD tfGva;
    QWORD args[4];

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntDetGetArguments(Detour, 4, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    erGva = args[0];
    efGva = args[1];
    tfGva = args[2];
    prevMode = args[3];

    STATS_ENTER(statsUmCrash);

    pRegs = &gVcpu->Regs;

    // we only care about user mode
    if (KERNEL_MODE == prevMode)
    {
        status = INT_STATUS_SUCCESS;
        goto _cleanup_and_exit;
    }

    if (gGuest.Guest64)
    {
        EXCEPTION_RECORD64 er = { 0 };

        status = IntKernVirtMemRead(erGva, sizeof(EXCEPTION_RECORD64), &er, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", pRegs->Rcx, status);
            goto _cleanup_and_exit;
        }

        // translate from KI_INTERNAL_EXCEPTION to a NTSTATUS value and also determine if we should care about
        // this exception
        if (!IntWinPreProcessException(er.ExceptionCode, &er.ExceptionCode))
        {
            goto _cleanup_and_exit;
        }

        if ((EXCEPTION_INT_DIVIDE_BY_ZERO == er.ExceptionCode) &&
            (IS_KERNEL_POINTER_WIN(gGuest.Guest64, er.ExceptionAddress)))
        {
            status = INT_STATUS_SUCCESS;
            goto _cleanup_and_exit;
        }

        if (IS_DEP_FAULT(er))
        {
            STATS_ENTER(statsDepViolation);

            status = IntWinCrashHandleDepViolation(&er, efGva, tfGva);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinCrashHandleDepViolation failed: 0x%08x\n", status);
            }

            STATS_EXIT(statsDepViolation);
        }

        status = IntWinSetUmExceptionEvent(&er);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSendUmExceptionEvent failed: 0x%08x\n", status);
            goto _cleanup_and_exit;
        }
    }
    else
    {
        EXCEPTION_RECORD32 er = { 0 };

        // read the exception record structure
        status = IntKernVirtMemRead(erGva, sizeof(EXCEPTION_RECORD32), &er, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", erGva, status);
            goto _cleanup_and_exit;
        }

        // translate from KI_INTERNAL_EXCEPTION to a INTSTATUS value and also determine if we should care about this
        // exception
        if (!IntWinPreProcessException(er.ExceptionCode, &er.ExceptionCode))
        {
            goto _cleanup_and_exit;
        }

        if (IS_DEP_FAULT(er))
        {
            STATS_ENTER(statsDepViolation);

            // There is no need for the exception frame on 32-bit, so NULL is ok here
            status = IntWinCrashHandleDepViolation(&er, 0, tfGva);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinCrashHandleDepViolation failed: 0x%08x\n", status);
            }

            STATS_EXIT(statsDepViolation);
        }

        status = IntWinSetUmExceptionEvent(&er);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSendUmExceptionEvent failed: 0x%08x\n", status);
            goto _cleanup_and_exit;
        }
    }

_cleanup_and_exit:

    STATS_EXIT(statsUmCrash);

    return INT_STATUS_SUCCESS;
}
