/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixcrash.h"
#include "alerts.h"
#include "decoder.h"
#include "guests.h"
#include "lixksym.h"


#define MAX_STACKTRACES             16
#define MAX_FUNC_NAME               128
#define MAX_LOG_SIZE                512

#define PREFIX_MAX              32
#define LOG_LINE_MAX            (1024 - PREFIX_MAX)


///
/// @brief The signal for STOP action.
///
#define LIX_SIGNAL_STOP_MASK (              \
        BIT(SIGSTOP)   |  BIT(SIGTSTP)   |  \
        BIT(SIGTTIN)   |  BIT(SIGTTOU)      )

///
/// @brief The signal for IGNORE action.
///
#define LIX_SIGNAL_IGNORE_MASK (\
        BIT(SIGCONT)   |  BIT(SIGCHLD)   | \
        BIT(SIGWINCH)  |  BIT(SIGURG)    )

///
/// @brief Check if the provided signal is fatal.
///
/// The possible effects an unblocked signal set to SIG_DFL can have are:
/// *   ignore      - Nothing Happens.
/// *   terminate   - kill the process, i.e. all threads in the group.
/// *   coredump    - write a core dump file describing all threads using the same mm and then kill all those threads.
/// *   stop        - stop all the threads in the group, i.e. TASK_STOPPED state
///
/// NOTE: For more information see include/linux/signal.h (linux kernel).
///
#define LIX_SIGNAL_FATAL(sig)   \
    !((sig) > 0 && (sig) < SIGRTMIN && (BIT(sig) & (LIX_SIGNAL_IGNORE_MASK | LIX_SIGNAL_STOP_MASK)))


///
/// @brief Linux 'struct printk_log' buffer header
///
typedef struct _PRINTK_LOG_HEADER
{
    QWORD   TimeStamp;
    WORD    RecordLength;
    WORD    TextLength;
    WORD    DirectoryLength;
    BYTE    Facility;
    BYTE    Flags: 5;
    BYTE    Level: 3;
} PRINTK_LOG_HEADER, *PPRINTK_LOG_HEADER;


static INTSTATUS
IntLixCrashSendPanicEvent(
    void
    )
///
/// @brief Send an event, if the operating system crashed, that contains information about the task that generated the
/// crash.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_CRASH_EVENT *pCrashEvent = &gAlert.Crash;

    memzero(pCrashEvent, sizeof(*pCrashEvent));

    IntAlertFillLixCurrentProcess(&pCrashEvent->CurrentProcess);

    status = IntNotifyIntroEvent(introEventCrashEvent, pCrashEvent, sizeof(*pCrashEvent));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyIntroEvent failed: %08x\n", status);
    }

    return status;
}


static INTSTATUS
IntLixCrashFetchDmesgSymbol(
    _Out_ QWORD *LogBufferGva,
    _Out_ QWORD *LogBufferLengthGva,
    _Out_ QWORD *LogFirstIdxGva
    )
///
/// @brief Find the address of the symbols 'log_buf', 'log_buf_len' and 'log_first_idx'.
///
/// This function tries to search the using IntKsymFindByName; this search may fail because on Debian the symbol
/// is not exported. If the symbol is not exported, the 'log_buf_kexec_setup' function is used to find these symbols.
/// This function initialize the 'log_buf', 'log_len', 'log_first_idx' calling the VMCOREINFO_SYMBOL; knowing these we
/// search for the first three MOV instructions that have the format MOV RDX, immediate and read the immediate value.
///
/// @param[out] LogBufferGva        Contains, on success, the address of 'log_buf'.
/// @param[out] LogBufferLengthGva  Contains, on success, the address of 'log_buf_len'.
/// @param[out] LogFirstIdxGva      Contains, on success, the address of 'log_first_idx'.
///
/// @retval #INT_STATUS_SUCCESS      On success.
/// @retval #INT_STATUS_NOT_FOUND    If at symbols is not found.
///
{
    INTSTATUS status;
    QWORD ksymLogBuffer;
    QWORD ksymLogBufferLength = 0;
    QWORD ksymLogFirstIdx = 0;
    QWORD ksymStart = 0;
    QWORD ksymEnd = 0;
    QWORD ksymOffset;

    ksymLogBuffer = IntKsymFindByName("log_buf", NULL);
    if (!ksymLogBuffer)
    {
        goto _disassemble;
    }

    ksymLogBufferLength = IntKsymFindByName("log_buf_len", NULL);
    if (!ksymLogBufferLength)
    {
        goto _disassemble;
    }

    ksymLogFirstIdx = IntKsymFindByName("log_first_idx", NULL);
    if (!ksymLogFirstIdx)
    {
        goto _disassemble;
    }

    *LogBufferGva = ksymLogBuffer;
    *LogBufferLengthGva = ksymLogBufferLength;
    *LogFirstIdxGva = ksymLogFirstIdx;

    TRACE("[LIX CRASH] Found 'log_buf' at %llx, 'log_buf_len' at %llx and 'log_first_idx' at 0x%llx\n",
          ksymLogBuffer, ksymLogBufferLength, ksymLogFirstIdx);

    return INT_STATUS_SUCCESS;

_disassemble:
    ksymStart = IntKsymFindByName("log_buf_kexec_setup", &ksymEnd);
    if (!ksymStart)
    {
        ERROR("[ERROR] IntKsymFindByName could not find log_buf_kexec_setup\n");
        return INT_STATUS_NOT_FOUND;
    }

    // VMCOREINFO_SYMBOL(log_buf);
    // VMCOREINFO_SYMBOL(log_buf_len);
    ksymLogBuffer = 0;
    ksymLogBufferLength = 0;
    ksymOffset = 0;
    while (ksymStart + ksymOffset < ksymEnd)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, ksymStart + ksymOffset, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed with status: 0x%08x.\n", status);
            ksymOffset++;
            continue;
        }

        ksymOffset += instrux.Length;

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Reg == NDR_RDX &&
            instrux.Operands[1].Type == ND_OP_IMM &&
            IS_KERNEL_POINTER_LIX(instrux.Operands[1].Info.Immediate.Imm))
        {
            // RDX contains log_buf/log_buf_len address; 3rd argument of VMCOREINFO_SYMBOL
            if (0 == ksymLogBuffer)
            {
                ksymLogBuffer = instrux.Operands[1].Info.Immediate.Imm;
            }
            else if (0 == ksymLogBufferLength)
            {
                ksymLogBufferLength = instrux.Operands[1].Info.Immediate.Imm;
            }
            else if (0 == ksymLogFirstIdx)
            {
                ksymLogFirstIdx = instrux.Operands[1].Info.Immediate.Imm;
            }

            if (ksymLogBuffer && ksymLogBufferLength && ksymLogFirstIdx)
            {
                *LogBufferGva = ksymLogBuffer;
                *LogBufferLengthGva = ksymLogBufferLength;
                *LogFirstIdxGva = ksymLogFirstIdx;

                TRACE("[LIX CRASH] Found 'log_buf' at %llx, 'log_buf_len' at %llx and 'log_buf_idx' at %llx\n",
                      ksymLogBuffer, ksymLogBufferLength, ksymLogFirstIdx);

                return INT_STATUS_SUCCESS;
            }
        }
    }

    return INT_STATUS_NOT_FOUND;
}


static BOOLEAN
IntLixCrashEnoughHeapAvailable(
    _In_ DWORD Size
    )
///
/// @brief Checks if the size of the free heap is bigger than the provided size.
///
/// @param[in] Size   The size needed to map the 'dmesg' buffer
///
/// @retval #INT_STATUS_SUCCESS True if there's enough heap to map the 'dmesg' buffer, otherwise false
///
{
    size_t totalHeapSize, freeHeapSize;

    INTSTATUS status = IntQueryHeapSize(&totalHeapSize, &freeHeapSize);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntQueryHeapSize failed: 0x%08x.\n", status);
        return FALSE;
    }

    return (freeHeapSize >= Size);
}


INTSTATUS
IntLixTaskSendExceptionEvent(
    _In_ DWORD Signal,
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Sends an event that contains the information about signal received by the provided task.
/// This function sends the event only if the guest options has the INTRO_OPT_EVENT_PROCESS_CRASH flag.
///
/// @param[in] Signal    The signal number sent to the task.
/// @param[in] Task      The task that received the signal.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the INTRO_OPT_EVENT_PROCESS_CRASH flag is not set.
///
{
    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_PROCESS_CRASH))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_EXCEPTION_EVENT *pEvent = &gAlert.Exception;
    LIX_TRAP_FRAME trapFrame = { 0 };

    memzero(pEvent, sizeof(*pEvent));

    pEvent->ExceptionCode = Signal;

    status = IntLixTaskGetTrapFrame(Task, &trapFrame);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixTaskGetTrapFrame failed with status: 0x%08x\n", status);
        pEvent->Rip = 0;
    }
    else
    {
        pEvent->Rip = trapFrame.Rip;
    }

    pEvent->Continuable = !LIX_SIGNAL_FATAL(Signal);

    IntAlertFillLixProcess(Task, &pEvent->CurrentProcess);

    TRACE("[UMEXCEPTION] Code: 0x%08x at RIP 0x%016llx inside process '%s' (Pid %d, Cr3 0x%016llx). Continuable: %d\n",
          Signal, pEvent->Rip, pEvent->CurrentProcess.ImageName, pEvent->CurrentProcess.Pid,
          pEvent->CurrentProcess.Cr3, pEvent->Continuable);

    status = IntNotifyIntroEvent(introEventExceptionEvent, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntLixCrashHandle(
    _In_ void *Detour
    )
///
/// @brief Sends an event that contains the information about signal received by the current task.
/// This function overwrite the return value of the 'complete_signal' with SIGKILL if the current task must be killed;
/// the current task must be killed if an exploit has been detected by the introspection engine.
///
/// @param[in] Detour   The internal detour structure.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Detour);

    LIX_TASK_OBJECT *pTask = IntLixTaskFindByGva(gVcpu->Regs.R8);
    if (!pTask)
    {
        WARNING("[WARNING] IntLixTaskFindByGva failed for process 0x%016llx\n", gVcpu->Regs.R8);
        goto _exit;
    }

    IntLixTaskSendExceptionEvent((DWORD)(gVcpu->Regs.R9), pTask);

_exit:
    if (pTask && pTask->MustKill)
    {
        LOG("[SIGNAL] Override signal %d with SIGKILL for task %llx\n",
            (DWORD)(gVcpu->Regs.R9), pTask->Gva);
    }

    INTSTATUS status = IntDetSetReturnValue(Detour, &gVcpu->Regs, (pTask && pTask->MustKill) ? SIGKILL : 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: %08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


void
IntLixCrashDumpDmesg(
    void
    )
///
/// @brief Dumps the 'dmesg' buffer from guest.
///
/// This function search for the 'log_buf', 'log_buf_len' and 'first_idx' and parse the buffer. For Linux kernel 2.6 the
/// 'dmesg' is a continuously buffer of chars. For kernel versions bigger than 2.6 the 'dmesg' has a header 'printk_log'
/// for each line.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    CHAR dmesgLine[LOG_LINE_MAX];
    PRINTK_LOG_HEADER *pHeader = NULL;
    char *pLogBufferStart = NULL;
    char *pLogBufferEnd = NULL;
    QWORD logBufferPointerGva, logBufferLengthGva, logFirstIdxGva;
    QWORD logBufferGva;
    DWORD logBufferLength, logFirstIdx;
    QWORD maxIterations = 0x10000;

    status = IntLixCrashFetchDmesgSymbol(&logBufferPointerGva, &logBufferLengthGva, &logFirstIdxGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixCrashFetchDmesgSymbol failed: 0x%08x\n", status);
        return;
    }

    status = IntKernVirtMemFetchQword(logBufferPointerGva, &logBufferGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", logBufferGva, status);
        return;
    }

    status = IntKernVirtMemFetchDword(logBufferLengthGva, &logBufferLength);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchDword failed for %llx: 0x%08x\n", logBufferLengthGva, status);
        return;
    }

    status = IntKernVirtMemFetchDword(logFirstIdxGva, &logFirstIdx);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchDword failed for %llx: 0x%08x\n", logFirstIdxGva, status);
        return;
    }

    if (!IntLixCrashEnoughHeapAvailable(logBufferLength))
    {
        WARNING("[WARNING] Not enough heap is available (requested %d bytes)\n", logBufferLength);
        return;
    }

    status = IntVirtMemMap(logBufferGva, logBufferLength, gGuest.Mm.SystemCr3, 0, &pLogBufferStart);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed with status 0x%08x for @%llx.", status, logBufferGva);
        return;
    }

    if (gLixGuest->Version.Version < 3)
    {
        for (DWORD index = 0; index < logBufferLength; index++)
        {
            DWORD indexLine = 0;
            while ((indexLine < sizeof(dmesgLine) - 1) &&
                   (index < logBufferLength) &&
                   (pLogBufferStart[index] != '\n'))
            {
                // The overflow (pLogBufferStart) check should be made using 'index' var because this is incremented
                // after each copied char.
                dmesgLine[indexLine++] = pLogBufferStart[index];
                index++;
            }

            dmesgLine[indexLine] = 0;
            LOG("[DMESG]%s", dmesgLine);
        }

        goto _exit;
    }

    pLogBufferEnd = pLogBufferStart + logBufferLength;

    pHeader = (PRINTK_LOG_HEADER *)(pLogBufferStart + logFirstIdx);

    LOG("[INFO] start_idx is: %d", logFirstIdx);

    while (--maxIterations)
    {
        size_t toPrint;
        const char *line = NULL;

        if ((char *)pHeader + sizeof(*pHeader) >= pLogBufferEnd)
        {
            ERROR("[ERROR] In-guest DMESG buffer may be corrupted!\n");
            break;
        }

        if (0 == pHeader->TextLength && logFirstIdx > 0)
        {
            LOG("[INFO] pHeader->TextLength is 0, will start from the beginning!");
            pHeader = (PRINTK_LOG_HEADER *)pLogBufferStart;
            continue;
        }

        if (!pHeader->RecordLength)
        {
            LOG("[DMESG] End of DMESG\n");
            break;
        }

        toPrint = pHeader->TextLength + 1ull;

        if (toPrint > sizeof(dmesgLine))
        {
            WARNING("[WARNING] TextLength %lu is bigger than our buffer size: %lu\n",
                    toPrint, sizeof(dmesgLine));

            toPrint = sizeof(dmesgLine);
        }

        line = (const char *)pHeader + sizeof(*pHeader);

        if (line + toPrint >= pLogBufferEnd)
        {
            ERROR("[ERROR] Last dmesg line is outside the mapped buffer. Will stop.");
            break;
        }

        memcpy(dmesgLine, line, toPrint);

        // Make sure the NULL terminator is there
        dmesgLine[toPrint - 1] = 0;

        LOG("[DMESG] [%llu.%llu] %s\n", NSEC_TO_SEC(pHeader->TimeStamp), NSEC_TO_USEC(pHeader->TimeStamp), dmesgLine);

        pHeader = (PRINTK_LOG_HEADER *)((BYTE *)pHeader + pHeader->RecordLength);
    }

    if (!maxIterations)
    {
        WARNING("[WARNING] Reached max iterations count. DMESG log may be truncated!");
    }
_exit:

    IntVirtMemUnmap(&pLogBufferStart);
}


INTSTATUS
IntLixCrashPanicHandler(
    _In_ void *Detour
    )
///
/// @brief Called if the 'panic' or 'kcrash_exec' handler is hit.
///
/// This function dumps the 'dmesg' buffer and send an crash event; also set the disable and the bugcheck vars to true
/// in order to uninit the introspection.
///
/// @param[in]  Detour  The internal detour structure.
///
/// @retval #INT_STATUS_DISABLE_DETOUR_ON_RET     The detours must be removed/disabled because the guest crashed.
{
    UNREFERENCED_PARAMETER(Detour);

    IntLixCrashDumpDmesg();

    IntLixCrashSendPanicEvent();

    gGuest.DisableOnReturn = TRUE;

    return IntGuestUninitOnBugcheck(Detour);
}
